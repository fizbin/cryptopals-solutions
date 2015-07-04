module Set2.PKCS7Padding where

import Control.Monad (guard)
import qualified Data.ByteString as B
import Data.Word (Word8)

unpad :: Int -> B.ByteString -> Maybe B.ByteString
unpad bSize bStr =
  let (nBlocks, rBlock) = B.length bStr `divMod` bSize
      lastByte = B.last bStr
      intendedPad = B.replicate (fromIntegral lastByte) lastByte
  in do
    guard $ bSize < fromIntegral (maxBound :: Word8)
    guard $ rBlock == 0
    guard $ nBlocks > 0
    guard $ lastByte > 0
    guard $ lastByte <= fromIntegral bSize
    guard $ B.isSuffixOf intendedPad bStr
    return $ B.take (B.length bStr - fromIntegral lastByte) bStr

pad :: Int -> B.ByteString -> B.ByteString
pad bSize bStr =
  let rBlock = B.length bStr `mod` bSize
      padLength = bSize - rBlock
      padding = B.replicate padLength (fromIntegral padLength)
  in bStr `B.append` padding
