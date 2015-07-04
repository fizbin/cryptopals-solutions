module Set1.DetectSingleCharXOR where

import qualified Set1.SingleByteXORCipher as Single
import Set1.HexToB64
import Data.ByteString.Char8 (ByteString)

findBestXOR :: [ByteString] -> ByteString
findBestXOR = go (fromHex' "00", Single.logLikelihood $ fromHex' "00")
  where
    go (best, _) [] = best
    go (best, bestScore) (s:ss) =
      let score = Single.logLikelihood $ snd $ Single.solve s
      in if score > bestScore
         then go (s, score) ss
         else go (best, bestScore) ss

findSingleXOR :: String -> IO (String, ByteString)
findSingleXOR fileName = do
  contents <- readFile fileName
  let hexLines = lines contents
      bStrings' = mapM fromHex hexLines
  bStrings <- either fail return bStrings'
  let bestBString = findBestXOR bStrings
      bestSolved = snd $ Single.solve bestBString
  return (toHex bestBString, bestSolved)

answer :: IO (String, ByteString)
answer = findSingleXOR "static/4.txt"
