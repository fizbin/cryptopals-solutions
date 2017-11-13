{-# LANGUAGE OverloadedStrings #-}

-- module Set4.HMACVerifyWebService where

import qualified Network.Wai as Wai
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Control.Concurrent (threadDelay)
import Network.HTTP.Types
import Control.Monad
import qualified Data.ByteArray as DBA
import Data.Monoid
import Data.Maybe (listToMaybe, fromMaybe)
import Data.Word
import Foreign (Ptr, peekElemOff)
import Set1.HexToB64
import Crypto.MAC.HMAC (hmac, HMAC(..))
import Crypto.Hash.Algorithms (SHA1)
import Crypto.Random (getRandomBytes)
import Network.Wai.Handler.Warp (runSettings, defaultSettings, setPort, setHost)


app :: B.ByteString -> Wai.Application
app key request respond =
  case Wai.rawPathInfo request of
    "/" -> respond index
    "/test" -> testHMAC key request respond
    _ -> respond notFound

index :: Wai.Response
index = Wai.responseLBS ok200 [("Content-type", "text/plain")]
        $ "The index. hit " <>
        "/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51" <>
        " or whatever to do the thing.\n"

notFound :: Wai.Response
notFound = Wai.responseLBS status404 [("Content-type", "text/plain")]
           "No.\r\n\r\n"

insecureCompare :: (DBA.ByteArrayAccess a, DBA.ByteArrayAccess b) =>
                   a -> b -> IO Bool
insecureCompare a b = do
  let byteSleep = threadDelay 50000 -- arg is microseconds; 5000 = 5ms
      aLen = DBA.length a
      bLen = DBA.length b
      doComparison :: Ptr Word8 -> Ptr Word8 -> Int -> IO Bool
      doComparison pH pS i = do
        byteSleep
        if i >= min aLen bLen then
          return (aLen == bLen)
          else do
          hByte <- peekElemOff pH i
          sByte <- peekElemOff pS i
          if hByte /= sByte then return False
            else doComparison pH pS (i+1)
  DBA.withByteArray a $ \pH ->
    DBA.withByteArray b $ \pS ->
    doComparison pH pS 0

testHMAC :: B.ByteString -> Wai.Application
testHMAC key request respond =
  let qstr = Wai.queryString request
      fileVal = fromMaybe "" (
        join $ snd <$> listToMaybe (filter ((== "file") . fst) qstr))
      sigHex = fromMaybe "" (
        join $ snd <$> listToMaybe (filter ((== "signature") . fst) qstr))
      sig = either (const "") id (fromHex $ B8.unpack sigHex)
      computedHMAC = hmac key fileVal :: HMAC SHA1
      rejected = Wai.responseLBS status403 [("Content-type", "text/plain")]
                 "BAD signature\r\nREJECTED\r\n"
      accepted = Wai.responseLBS ok200 [("Content-type", "text/plain")]
                 "Good signature\r\n"
  in do
    isEq <- insecureCompare computedHMAC sig
    respond (if isEq then accepted else rejected)

main :: IO ()
main = do
  key <- getRandomBytes 32
  forM_ ["cat", "dog", "foo", "bog"] $ \fileVal -> do
    let computedHMAC = hmac key fileVal :: HMAC SHA1
        sigHex = toHex $ B.pack . DBA.unpack $ computedHMAC
    putStrLn ("http://localhost:9000/test?file=" ++ B8.unpack fileVal
              ++ "&signature=" ++ sigHex)
  putStrLn "http://localhost:9000/"
  runSettings (setHost "127.0.0.1" $ setPort 9000 defaultSettings) (app key)
