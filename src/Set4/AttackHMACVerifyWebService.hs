{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}

--module Set4.AttackHMACVerifyWebService where

import Control.Concurrent (threadDelay)
import "async" Control.Concurrent.Async (mapConcurrently)
import Control.Exception
import Control.Monad
import Control.Monad.Except
import Data.List (elemIndex, sort)
import Data.Maybe (fromMaybe)
import Data.Monoid
import Data.Time
import Data.Word
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Network.HTTP.Client
import Network.HTTP.Types
import Set1.HexToB64
import Control.Concurrent.QSem
import System.Environment
import System.Random.Shuffle

attackOneByte :: B.ByteString -> B.ByteString -> B.ByteString -> Int
              -> IO (Either Word8 B.ByteString)
attackOneByte urlPrefix file sigPrefix nTimings =
  fmap (either Right Left) $ runExceptT $ do
  manager <- lift $ newManager defaultManagerSettings
  rawTimings <- replicateM nTimings (getTimings manager)
  let allTimings = foldr (zipWith (:)) (repeat []) rawTimings
      aggregate ts = let ts' = sort ts
                         ts'' = take ((2 + length ts') `div` 3) ts'
                     in sum ts'' / fromIntegral (length ts'')
      timings = map aggregate allTimings
      maxTime = maximum timings :: Double
      restTimes = filter (< maxTime) timings
      avgRest = sum restTimes / 255
      maxRest = maximum restTimes
      minTime = minimum timings
  if (maxTime - maxRest < 2*(maxRest - avgRest))
     || (maxTime - maxRest < maxRest - minTime)
    then do liftIO $ putStrLn $ "Remeasuring... "
              ++ show (nTimings, maxTime, maxRest, avgRest, minTime)
            y <- lift $ attackOneByte urlPrefix file sigPrefix (nTimings * 2)
            either return throwError y
    else case elemIndex maxTime timings of
           Just x -> pure $ fromIntegral x
           Nothing -> error "max not in list"
  where
    getTimings :: Manager -> ExceptT B.ByteString IO [Double]
    getTimings manager = fmap (map snd . sort) . convTimings $ do
      qsem <- liftIO $ newQSem 4
      bytes <- liftIO $ shuffleM [minBound..maxBound :: Word8]
      liftIO $ flip mapConcurrently bytes $
        \b -> bracket_ (waitQSem qsem) (signalQSem qsem) $ runExceptT $ do
          -- manager <- lift $ newManager defaultManagerSettings
          liftIO $ threadDelay 100
          startUTC <- lift getCurrentTime
          let request = parseRequest' $ urlPrefix <>
                renderSimpleQuery True [("file", file),
                                        ("signature",
                                         B8.pack $ toHex $ B.snoc sigPrefix b)]
          (status, endUTC) <- lift $ catchJust selectResponse
            (withResponse request manager handleResponse) handleResponse
          when (statusCode status == 200) (throwError $ B.snoc sigPrefix b)
          return (b, fromRational $ toRational $ diffUTCTime endUTC startUTC)
    convTimings x = fmap sequence x >>= either throwError return
    handleResponse :: Response t -> IO (Status, UTCTime)
    handleResponse r =  do
      let status = responseStatus r
      (,) status <$> getCurrentTime
    parseRequest' bs =
      let p = parseRequest (B8.unpack bs)
      in fromMaybe (error $ "Invalid url " ++ show bs) p

selectResponse :: HttpException -> Maybe (Response ())
selectResponse e = case e of
  HttpExceptionRequest _ (StatusCodeException resp _) -> Just resp
  _ -> Nothing

attackURL :: B.ByteString -> B.ByteString -> IO ()
attackURL target fileVal = attackURLFrom ""
  where
    attackURLFrom prefix = do
      putStrLn $ "Found " ++ show (toHex prefix)
      attackResult <- attackOneByte target fileVal prefix 10
      case attackResult of
        Left b -> attackURLFrom (B.snoc prefix b)
        Right sig -> putStrLn $ "Signature is " ++ toHex sig

main :: IO ()
main = do
  args <- getArgs
  case args of
    [a, b] -> attackURL (B8.pack a) (B8.pack b)
    _ -> putStrLn "Usage: prog url fileval"
