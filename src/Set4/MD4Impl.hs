{-# LANGUAGE OverloadedStrings #-}

module Set4.MD4Impl where

import Control.Monad
import Control.Monad.Reader
import Control.Monad.State
import Data.Bits
import Data.Word
import Data.Monoid
import Data.Binary.Get
import Data.Binary.Put
import Data.Array.IArray as DA
import qualified Data.Array.Unboxed as DAU
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL

md4_preproc :: B.ByteString -> B.ByteString
md4_preproc bs = let bs' = bs <> "\x80"
                     bsplen = 8 * B.length bs'
                     extraNeeded = if bsplen `mod` 512 <= 448
                                   then 448 - (bsplen `mod` 512)
                                   else 1024 - 64 - (bsplen `mod` 512)
                     -- Unlike SHA1, note little endian!
                     bslenenc = BL.toStrict $ runPut $ putWord64le $
                                fromIntegral (8 * B.length bs)
                  in bs' <> B.replicate (extraNeeded `div` 8) 0 <> bslenenc

md4_F :: Word32 -> Word32 -> Word32 -> Word32
md4_F x y z = (x .&. y) .|. (complement x .&. z)

md4_G :: Word32 -> Word32 -> Word32 -> Word32
md4_G x y z = (x .&. y) .|. (x .&. z) .|. (y .&. z)

md4_H :: Word32 -> Word32 -> Word32 -> Word32
md4_H x y z = x `xor` y `xor` z

md4_processChunk :: B.ByteString -> (Word32, Word32, Word32, Word32)
                 -> (Word32, Word32, Word32, Word32)
md4_processChunk chunk s0@(aa, bb, cc, dd) = flip evalState s0 $ do
  -- Round1
  flip runReaderT md4_F $ do
    mABCD 0 3  >> mDABC 1 7  >> mCDAB 2 11  >> mBCDA 3 19
    mABCD 4 3  >> mDABC 5 7  >> mCDAB 6 11  >> mBCDA 7 19
    mABCD 8 3  >> mDABC 9 7  >> mCDAB 10 11 >> mBCDA 11 19
    mABCD 12 3 >> mDABC 13 7 >> mCDAB 14 11 >> mBCDA 15 19

  -- Round2
  flip runReaderT (\x y z -> md4_G x y z + 0x5A827999) $ do
    mABCD 0 3 >> mDABC 4 5 >> mCDAB 8 9  >> mBCDA 12 13
    mABCD 1 3 >> mDABC 5 5 >> mCDAB 9 9  >> mBCDA 13 13
    mABCD 2 3 >> mDABC 6 5 >> mCDAB 10 9 >> mBCDA 14 13
    mABCD 3 3 >> mDABC 7 5 >> mCDAB 11 9 >> mBCDA 15 13

  -- Round3
  flip runReaderT (\x y z -> md4_H x y z + 0x6ED9EBA1) $ do
    mABCD 0 3 >> mDABC 8 9  >> mCDAB 4 11 >> mBCDA 12 15
    mABCD 2 3 >> mDABC 10 9 >> mCDAB 6 11 >> mBCDA 14 15
    mABCD 1 3 >> mDABC 9 9  >> mCDAB 5 11 >> mBCDA 13 15
    mABCD 3 3 >> mDABC 11 9 >> mCDAB 7 11 >> mBCDA 15 15

  (a, b, c, d) <- get
  return (a + aa, b + bb, c + cc, d + dd)
  where
    xX :: DAU.UArray Int Word32
    xX = listArray (0, 15) $
         runGet (replicateM 16 getWord32le) (BL.fromStrict chunk)
    mABCD, mDABC, mCDAB, mBCDA :: Int -> Int
      -> ReaderT (Word32 -> Word32 -> Word32 -> Word32)
         (State (Word32, Word32, Word32, Word32)) ()
    mABCD k s = do (a, b, c, d) <- get
                   f <- ask
                   let inc = f b c d + (DA.!) xX k
                   put ((a + inc) `rotate` s, b, c, d)
    mDABC k s = do (a, b, c, d) <- get
                   f <- ask
                   let inc = f a b c + (DA.!) xX k
                   put (a, b, c, (d + inc) `rotate` s)
    mCDAB k s = do (a, b, c, d) <- get
                   f <- ask
                   let inc = f d a b + (DA.!) xX k
                   put (a, b, (c + inc) `rotate` s, d)
    mBCDA k s = do (a, b, c, d) <- get
                   f <- ask
                   let inc = f c d a + (DA.!) xX k
                   put (a, (b + inc) `rotate` s, c, d)

md4' :: (Word32, Word32, Word32, Word32) -> [B.ByteString]
      -> B.ByteString
md4' s0 chunks = flip evalState s0 $ do
  forM_ chunks $ modify . md4_processChunk
  (a, b, c, d) <- get
  return $ BL.toStrict $ runPut $
    putWord32le a >> putWord32le b >> putWord32le c >> putWord32le d

md4 :: B.ByteString -> B.ByteString
md4 bs =
  let bs' = md4_preproc bs
      chunkify b = if B.null b then []
                   else let (b1, b2) = B.splitAt 64 b
                        in b1 : chunkify b2
      chunks = chunkify bs'
  in md4' (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476) chunks
