{-# LANGUAGE ScopedTypeVariables #-}

module Set3.ImplementMT19937 (
  Twisted
  , TwistedConfig
  , mt19937
  , mt19937_64
  , newTwisted
  , pullTwisted
  )
where

import Control.Arrow (first)
import Control.Monad.ST
import Data.Bits
import Data.ByteArray (pack)
import Data.Vector.Unboxed hiding (forM_, (++))
import qualified Data.Vector.Unboxed.Mutable as Mut
import Data.Word
import Data.Foldable (forM_)
import Crypto.Random
import Prelude as P


data Twisted itype = TwistedC (TwistedConfig itype) Int (Vector itype)

data TwistedConfig itype = TwistedConfigC {
  _tcW :: Int, _tcN :: Int, _tcM :: Int, _tcR :: Int,
  _tcA :: itype,
  _tcU :: Int, _tcD :: itype,
  _tcS :: Int, _tcB :: itype,
  _tcT :: Int, _tcC :: itype,
  _tcL :: Int,
  _tcF :: itype
  }

mt19937 :: TwistedConfig Word32
mt19937 = TwistedConfigC
          32 624 397 31 
          0x9908b0df
          11 0xffffffff
          7 0x9d2c5680
          15 0xefc60000
          18 1812433253

mt19937_64 :: TwistedConfig Word64
mt19937_64 = TwistedConfigC
             64 312 156 31
             0xb5026f5aa96619e9
             29 0x5555555555555555
             17 0x71d67fffeda60000
             37 0xfff7eee000000000
             43 6364136223846793005


newTwisted :: forall i. (Num i, Bits i, Unbox i) =>
              TwistedConfig i -> i -> Twisted i
newTwisted cfg seed = TwistedC cfg (_tcN cfg) (runST (mkArray >>= freeze))
  where
    mkArray :: ST s (MVector s i)
    mkArray = do
      ret <- Mut.new (_tcN cfg)
      Mut.write ret 0 seed
      forM_ [1.._tcN cfg - 1] $ \i -> do
        prev <- Mut.read ret (i-1)
        let n = _tcF cfg * (prev `xor` (prev `shiftR` (_tcW cfg - 2)))
                + fromIntegral i
        Mut.write ret i n
      return ret


pullTwisted :: (Integral i, Num i, Bits i, Unbox i) =>
               Twisted i -> (i, Twisted i)
pullTwisted tw@(TwistedC cfg _ _) = pullTwisted' tw
  where
    pullTwisted' (TwistedC _ i arr) | i >= _tcN cfg =
      pullFrom 0 (generateNums arr)
    pullTwisted' (TwistedC _ i arr) = pullFrom i arr
    pullFrom i arr =
      let y1 = arr ! i
          y2 = y1 `xor` ((y1 `shiftR` _tcU cfg) .&. _tcD cfg)
          y3 = y2 `xor` ((y2 `shiftL` _tcS cfg) .&. _tcB cfg)
          y4 = y3 `xor` ((y3 `shiftL` _tcT cfg) .&. _tcC cfg)
          y5 = y4 `xor` (y4 `shiftR` _tcL cfg)
      in (y5, TwistedC cfg (i+1) arr)
    genXOR y 0 = y `shiftR` 1
    genXOR y _ = (y `shiftR` 1) `xor` _tcA cfg
    lower_mask = (1 `shiftL` _tcR cfg) - 1
    upper_mask = complement lower_mask
    generateNums arr' = runST $ freeze =<< do
      arr <- thaw arr'
      forM_ [0.._tcN cfg - 1] $ \i -> do
        cur <- Mut.read arr i
        nxt <- Mut.read arr ((i+1) `mod` _tcN cfg)
        let y = (cur .&. upper_mask) + (nxt .&. lower_mask)
        far <- Mut.read arr ((i+_tcM cfg) `mod` _tcN cfg)
        Mut.write arr i $ far `xor` genXOR y (y `mod` 2)
      return arr

dumpData :: (Unbox i) => Twisted i -> (Int, [i])
dumpData (TwistedC _ i arr) = (i, toList arr)

instance (Integral i, Num i, Bits i, Unbox i) =>
         DRG (Twisted i) where
  randomBytesGenerate nbytes tcc@(TwistedC cfg _ _) =
    first pack $ grabbit tcc [] 0 0
    where
      tcW = _tcW cfg
      grabBytes :: Int -> i -> i -> ([Word8], Int, i)
      grabBytes 0 _ new = grab1 new
      grabBytes leftover old new =
        let (w', b', i') = grab1 new
            w1 = (old `shiftL` b') .|. i'
        in if leftover + b' < 8 then (w', leftover + b', w1)
           else let b'' = leftover + b' - 8
                    w1' = w1 `shiftR` 8
                in (fromIntegral w1:w', b'', w1')
      grab1 :: i -> ([Word8], Int, i)
      grab1 = grab1' tcW
      grab1' b i | b < 8 = ([], b, i)
      grab1' b i = let (w', b', i') = grab1' (b - 8) (i `shiftR` 8)
                       w = fromIntegral i :: Word8
                   in (w:w', b', i')
      grabbit tc accm _ _ | P.length accm >= nbytes =
        (P.take nbytes accm, tc)
      grabbit tc accm b i =
        let (new, tc') = pullTwisted tc
            (w', b', i') = grabBytes b i new
        in grabbit tc' (w' ++ accm) b' i'
