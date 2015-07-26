module Set3.CloneMT where

import Control.Arrow ((>>>))
import Set2.ECBCBCDetection (randomInt)
import Data.Bits
import Data.Vector.Unboxed (Unbox)
import Data.Word
import Set3.ImplementMT19937

-- undoes y' = y `xor` ((y `shiftL` s) .&. b)
untemperLeft :: (Bits w, Num w) => Int -> w -> w -> w
untemperLeft s b y' = go (complement 0) y'
  where
    go 0 y = y
    go mask y = let maskL = mask `shiftL` s
                    maskR = complement maskL
                    yish = (maskL .&. y') .|. (maskR .&. y)
                    tempered = yish `xor` ((yish `shiftL` s) .&. b)
                in go maskL ((maskL .&. tempered) .|. (maskR .&. y))

-- undoes y' = y `xor` ((y `shiftR` u) .&. d)
untemperRight :: (Bits w, Num w) => Int -> w -> w -> w
untemperRight u d y' = go (complement 0) y'
  where
    go 0 y = y
    go mask y = let maskR = mask `shiftR` u
                    maskL = complement maskR
                    yish = (maskL .&. y) .|. (maskR .&. y')
                    tempered = yish `xor` ((yish `shiftR` u) .&. d)
                in go maskR ((maskR .&. tempered) .|. (maskL .&. y))

untemper :: (Bits w, Num w) => TwistedConfig w -> w -> w
untemper cfg = untemperRight (_tcL cfg) (complement 0) >>>
               untemperLeft (_tcT cfg) (_tcC cfg) >>>
               untemperLeft (_tcS cfg) (_tcB cfg) >>>
               untemperRight (_tcU cfg) (_tcD cfg)

cloneMT :: (Bits w, Num w, Unbox w) => TwistedConfig w -> [w] -> Twisted w
cloneMT cfg output = let lastOut = reverse $ take (_tcN cfg) (reverse output)
                         state = map (untemper cfg) lastOut
                     in newFromState cfg  (_tcN cfg) state

twistedStream :: (Unbox i, Bits i, Integral i) => Twisted i -> [i]
twistedStream t = let (n, t') = pullTwisted t
                  in n : twistedStream t'

answer :: IO ()
answer = do
  seed <- randomInt 1 $ fromIntegral (maxBound :: Word32)
  let originalTwister = newTwisted mt19937 $ fromIntegral seed
      (taken, remainder) = splitAt 624 $ twistedStream originalTwister
      cloned = cloneMT mt19937 taken
      cloneStream = twistedStream cloned
  mapM_ print $ take 20 $ zip remainder cloneStream
