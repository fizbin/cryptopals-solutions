module Set1.SingleByteXORCipher where

import Set1.FixedXOR
import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString as B
import Data.Char (toUpper, ord, chr)
import Data.Word (Word8)
import qualified Data.Map as M
import Data.Map ((!))

frequencies :: M.Map Char Double
frequencies = M.fromList [
    ('E', 12.02)
  , ('T', 9.10)
  , ('A', 8.12)
  , ('O', 7.68)
  , ('I', 7.31)
  , ('N', 6.95)
  , ('S', 6.28)
  , ('R', 6.02)
  , ('H', 5.92)
  , ('D', 4.32)
  , ('L', 3.98)
  , ('U', 2.88)
  , ('C', 2.71)
  , ('M', 2.61)
  , ('F', 2.30)
  , ('Y', 2.11)
  , ('W', 2.09)
  , ('G', 2.03)
  , ('P', 1.82)
  , ('B', 1.49)
  , ('V', 1.11)
  , ('K', 0.69)
  , ('X', 0.17)
  , ('Q', 0.11)
  , ('J', 0.10)
  , ('Z', 0.07)
  , (' ', 10)
  , ('.', 0.2)
  , ('\'', 0.2)
  , (',', 0.2)
  , ('?', 0.2)
  ]

logFrequency :: M.Map Char Double
stdEntropy :: Double
(stdEntropy, logFrequency) = (stdEntropy',
                              M.fromList $ zip [chr 0..chr 255] freqBalanced)
  where
    freqRaw = map (\c ->
                    let def = if 32 <= ord c && ord c <= 127
                              then 0.001 else 0.00001
                    in M.findWithDefault def (toUpper c) frequencies)
              [chr 0..chr 255]
    freqBalanced = let tot = sum freqRaw in map (/ tot) freqRaw
    stdEntropy' = sum $ map (\p -> p * log p) freqBalanced

logLikelihood :: ByteString -> Double
logLikelihood b =
  sum (map (\x -> logFrequency ! x - stdEntropy) (BC.unpack b)) /
  fromIntegral (B.length b)

testByte :: Word8 -> ByteString -> Double
testByte b cText = logLikelihood $
                   fixedXOR (B.pack $ replicate (B.length cText) b) cText

solve :: ByteString -> (Word8, ByteString)
solve cText = (winningByte,
               fixedXOR (B.replicate (B.length cText) winningByte) cText)
  where
    winningByte = snd $
                  foldr checkMore (-20.0 * fromIntegral (B.length cText), 0)
                  [minBound..maxBound]
    checkMore nextByte (currentBest, currentAt) =
      let nextScore = testByte nextByte cText
      in if nextScore > currentBest then (nextScore, nextByte)
         else (currentBest, currentAt)
