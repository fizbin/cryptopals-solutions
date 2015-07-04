module Set1.BreakRepeatingKeyXOR where

import Control.Arrow ((&&&))
import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString as B
import Set1.HexToB64
import Set1.FixedXOR
import qualified Set1.RepeatingKeyXOR as Repeating
import qualified Set1.SingleByteXORCipher as Single
import Data.Bits
import Data.List (maximumBy, sortBy)
import Data.Function (on)
import Data.Word(Word8)
--import Debug.Trace (trace)

hammingDistance :: ByteString -> ByteString -> Int
hammingDistance bstr1 bstr2 = sum $ map bitCount $
                              B.unpack (fixedXOR bstr1 bstr2)
  where
    bitCount :: Word8 -> Int
    bitCount 0 = 0
    bitCount x = let b = bitCount (shiftR x 1)
                 in if testBit x 0 then 1 + b else b

scoreKeySize :: (Fractional a) => Int -> ByteString -> a
scoreKeySize keySize bytes = average (map (uncurry hammingDistance) $
                                      chunkPairs bytes) / fromIntegral keySize
  where
    chunkPairs bytes' = if B.length bytes' < 2*keySize then []
                        else let (chunk1, rest1) = B.splitAt keySize bytes'
                                 (chunk2, rest2) = B.splitAt keySize rest1
                             in (chunk1, chunk2) : chunkPairs rest2
    average = go 0 (0::Int)
      where
        go accum n [] = fromIntegral accum / fromIntegral n
        go accum n (x:xs) = go (accum + x) (n + 1) xs

solveWithKeySize :: Int -> ByteString -> (ByteString, ByteString)
solveWithKeySize keySize bytes =
  (bestKey, Repeating.encryptBB bestKey bytes)
  where
    byKeySize b | B.null b = []
    byKeySize b = let (c, rest) = B.splitAt keySize b
                  in c : byKeySize rest
    singlePuzzles = B.transpose (byKeySize bytes)
    bestKey = B.pack $ map (fst . Single.solve) singlePuzzles

solve :: ByteString -> (ByteString, ByteString)
solve bytes =
  let scoredKeySizes :: [(Int, Double)]
      scoredKeySizes = map (id &&& (`scoreKeySize` bytes)) [1..40]
      keySizes = map fst $ take 5 $
                 sortBy (compare `on` snd) scoredKeySizes
      solutions = map (`solveWithKeySize` bytes) keySizes
  in maximumBy (compare `on` (Single.logLikelihood . snd)) solutions

answer :: IO (ByteString, ByteString)
answer = do
  contents <- readFile "static/6.txt"
  bytes <- either fail return $ fromB64 contents
  return $ solve bytes
