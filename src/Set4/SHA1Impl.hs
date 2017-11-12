{-# LANGUAGE OverloadedStrings #-}

module Set4.SHA1Impl where

import Control.Monad
import Control.Monad.State
import Data.Bits
import Data.Word
import Data.Monoid
import qualified Data.ByteString as B

sha1_f :: Int -> Word32 -> Word32 -> Word32 -> Word32

sha1_f t b c d | t <= 19 = (b .&. c) .|. (complement b .&. d)
sha1_f t b c d | 20 <= t && t <= 39 = b `xor` c `xor` d
sha1_f t b c d | 40 <= t && t <= 59 =
                 (b .&. c) .|. (b .&. d) .|. (c .&. d)
sha1_f t b c d | 60 <= t && t <= 79 = b `xor` c `xor` d
sha1_f _ _ _ _ = error "t too large"

sha1_k :: Int -> Word32
sha1_k t | t <= 19 =            0x5A827999
sha1_k t | 20 <= t && t <= 39 = 0x6ED9EBA1
sha1_k t | 40 <= t && t <= 59 = 0x8F1BBCDC
sha1_k t | 60 <= t && t <= 79 = 0xCA62C1D6
sha1_k _ = error "t too large"

sha1_preproc :: B.ByteString -> B.ByteString
sha1_preproc bs = let bs' = bs <> "\x80"
                      bsplen = 8 * B.length bs'
                      extraNeeded = if bsplen `mod` 512 <= 448
                                    then 448 - (bsplen `mod` 512)
                                    else 1024 - 64 - (bsplen `mod` 512)
                      enc16 :: Word16 -> B.ByteString
                      enc16 x = B.singleton (fromIntegral $ x `shiftR` 8) <>
                                B.singleton (fromIntegral x)
                      enc32 :: Word32 -> B.ByteString
                      enc32 x = enc16 (fromIntegral $ x `shiftR` 16) <>
                                enc16 (fromIntegral x)
                      enc64 :: Word64 -> B.ByteString
                      enc64 x = enc32 (fromIntegral $ x `shiftR` 32) <>
                                enc32 (fromIntegral x)
                      bslenenc = enc64 . fromIntegral $ 8 * B.length bs
                  in bs' <> B.replicate (extraNeeded `div` 8) 0 <> bslenenc

word32be :: Word32 -> B.ByteString
word32be w = B.pack [ fromIntegral (w `shiftR` 24)
                    , fromIntegral (w `shiftR` 16)
                    , fromIntegral (w `shiftR` 8)
                    , fromIntegral w
                    ]

readWord32be :: B.ByteString -> Word32
readWord32be b =
  let (b0:b1:b2:b3:_) = B.unpack b
  in fromIntegral b0 `shiftL` 24
     .|. fromIntegral b1 `shiftL` 16
     .|. fromIntegral b2 `shiftL` 8
     .|. fromIntegral b3

sha1_processChunk :: B.ByteString -> (Word32, Word32, Word32, Word32, Word32)
                  -> (Word32, Word32, Word32, Word32, Word32)
sha1_processChunk chunk (h0, h1, h2, h3, h4) =
  flip evalState (h0, h1, h2, h3, h4) $ do
  when (B.length chunk /= 64) $ error "Invalid chunk length"
  forM_ w $ \(t, wi) -> do
    (a, b, c, d, e) <- get
    let f = sha1_f t b c d
        k = sha1_k t
        temp = (a `rotate` 5) + f + e + k + wi
    put (temp, a, b `rotate` 30, c, d)
  (h0', h1', h2', h3', h4') <- get
  return (h0 + h0', h1 + h1', h2 + h2', h3 + h3', h4 + h4')
  where
    w :: [(Int, Word32)]
    w = zip [0..] $ take 80 w'
    chunkAsW32s = let f b = if B.null b then []
                            else readWord32be b : f (B.drop 4 b)
                  in f chunk
    w' :: [Word32]
    w' = chunkAsW32s ++ map (`rotate` 1)
         (zipWith xor (zipWith xor (drop 13 w') (drop 8 w'))
           (zipWith xor (drop 2 w') w'))

sha1 :: B.ByteString -> B.ByteString
sha1 bs = flip evalState (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
                          0xC3D2E1F0) $ do
  let bs' = sha1_preproc bs
      chunkify b = if B.null b then []
                   else let (b1, b2) = B.splitAt 64 b
                        in b1 : chunkify b2
      chunks = chunkify bs'
  forM_ chunks $ \c -> modify (sha1_processChunk c)
  (h0, h1, h2, h3, h4) <- get
  return $ word32be h0 <> word32be h1 <> word32be h2 <> word32be h3
    <> word32be h4

