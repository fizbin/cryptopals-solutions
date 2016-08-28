{-# LANGUAGE ScopedTypeVariables #-}

module Set2.CBCBitFlip where

import Control.Applicative
import Crypto.Cipher.Types
import Crypto.Random
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.Monoid
import qualified Set1.HexToB64 as H
import Set1.FixedXOR
import qualified Set2.ImplementCBC as CBC
import qualified Set2.ECBCBCDetection as Detect

detectBlockLength :: (MonadRandom m) => (B.ByteString -> m B.ByteString)
                     -> m Int
detectBlockLength oracle = go ""
  where
    go bs = do
      let bs' = "a" <> bs
      l1 <- B.length <$> oracle bs
      l2 <- B.length <$> oracle bs'
      if l1 /= l2 then return (l2 - l1) else go bs'

firstM :: (Monad m) => (a -> m (Maybe b)) -> [a] -> m (Maybe b)
firstM _ [] = return Nothing
firstM p (x:xs) = do
  q <- p x
  case q of
    Just _ -> return q
    Nothing -> firstM p xs

breakOracles :: forall m. (MonadRandom m) =>
                (String -> m B.ByteString, B.ByteString -> Bool) ->
                m (Either String B.ByteString)
breakOracles (encrypter, checker) = do
  blockLen <- detectBlockLength (encrypter . BC.unpack)
  f <- firstM (tryUserDataLen blockLen) [blockLen+11 .. 4*blockLen+11]
  return $ case f of
    Just ans -> Right ans
    Nothing -> Left "Couldn't find it"
  where
    xorBit = fixedXOR ";admin=true" $ B.replicate 20 97
    tryUserDataLen :: Int -> Int -> m (Maybe B.ByteString)
    tryUserDataLen blockLen len = do
      ciphered <- encrypter $ BC.unpack $ B.replicate len 97
      let cLen = B.length ciphered
          initialSpots = [0,blockLen..cLen-1]
          checkString spot =
            fixedXOR (B.replicate spot 0 <> xorBit <> B.replicate cLen 0)
            ciphered
          checkSpots = map checkString initialSpots
          checkit str = return $ if checker str then Just str else Nothing
      firstM checkit checkSpots

mkOracles :: (BlockCipher c, MonadRandom m) =>
             c -> (String -> m B.ByteString, B.ByteString -> Bool)
mkOracles cipher = (encryptedProfileFor, isAdmin)
  where
    isAdmin cText =
      case CBC.decryptIVPadAttach cipher cText of
        Left _ -> False
        Right x -> ";admin=true;" `B.isInfixOf` x

    encryptedProfileFor userdata =
      CBC.encryptIVPadAttach cipher (BC.pack $ profileFor userdata)

    profileFor :: String -> String
    profileFor userdata = "comment1=cooking%20MCss;userdata=" <>
                          concatMap escaper userdata <>
                          ";comment2=%20like%20a%20pound%20of%20bacon"
      where
        escaper x | x `elem` (";%="::String) = "%" <> H.toHex (BC.singleton x)
        escaper x = [x]

answer :: IO ()
answer = do
  cipherAttempt <- Detect.randomAES
  cipher <- either fail return cipherAttempt
  let oracles = mkOracles cipher
  broken <- breakOracles oracles
  case broken of
    Left err -> fail err
    Right blob -> do
      putStrLn "Success"
      putStrLn $ "Blob: " ++ show blob
      putStrLn $ "Decodes as: " ++ show (CBC.decryptIVPadAttach cipher blob)
