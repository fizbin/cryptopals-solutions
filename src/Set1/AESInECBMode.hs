{-# LANGUAGE OverloadedStrings #-}

module Set1.AESInECBMode where

import Control.Monad (guard)
import Crypto.Cipher.Types
import Crypto.Cipher.AES
import Crypto.Error
import qualified Data.ByteString as B
import Data.Word (Word8)
import Set1.HexToB64

unpad :: Int -> B.ByteString -> Maybe B.ByteString
unpad bSize bStr =
  let (nBlocks, rBlock) = B.length bStr `divMod` bSize
      lastByte = B.last bStr
      intendedPad = B.replicate (fromIntegral lastByte) lastByte
  in do
    guard $ bSize < fromIntegral (maxBound :: Word8)
    guard $ rBlock == 0
    guard $ nBlocks > 0
    guard $ lastByte < fromIntegral bSize
    guard $ B.isSuffixOf intendedPad bStr
    return $ B.take (B.length bStr - fromIntegral lastByte) bStr

answer :: IO (Maybe B.ByteString)
answer = do
  contents <- readFile "static/7.txt"
  bytes <- either fail return $ fromB64 contents
  let key = "YELLOW SUBMARINE" :: B.ByteString
  cipher <- case cipherInit key of
    CryptoPassed x -> return (x :: AES128)
    CryptoFailed f -> fail (show f)
  return $ unpad (blockSize cipher) $ ecbDecrypt cipher bytes
