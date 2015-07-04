module Set1.FixedXOR where

import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import Data.Bits

fixedXOR :: ByteString -> ByteString -> ByteString
fixedXOR a b = B.pack $ B.zipWith xor a b
