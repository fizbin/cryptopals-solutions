module Set3.TimeBasedMT where

import Control.Applicative
import Set2.ECBCBCDetection (randomInt)
import Set3.ImplementMT19937
import Data.Time.Clock.POSIX
import Data.Word

newtype SecretSeed = SecretSeed Int deriving (Eq, Show)

makePuzzle :: IO (SecretSeed, Word32)
makePuzzle = do
  nowTS <- floor <$> getPOSIXTime
  randomOffset <- randomInt 80 2000
  let seed = nowTS - randomOffset
      twister = newTwisted mt19937 (fromIntegral seed)
  return (SecretSeed seed, fst (pullTwisted twister))

crackPuzzle :: Word32 -> IO [SecretSeed]
crackPuzzle target = do
  nowTS <- floor <$> getPOSIXTime
  let range = [nowTS - 3000 .. nowTS]
      acceptable x = let twister = newTwisted mt19937 (fromIntegral x)
                     in target == fst (pullTwisted twister)
  return $ map SecretSeed $ filter acceptable range

answer :: IO ()
answer = do
  puzzle <- makePuzzle
  print puzzle
  crackPuzzle (snd puzzle) >>= print
