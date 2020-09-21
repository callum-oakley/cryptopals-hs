{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}

import           Control.Applicative   (liftA2)
import           Control.Monad         (filterM, replicateM_, unless, void,
                                        when)
import           Data.Bits             (Bits, popCount, shiftL, shiftR, testBit,
                                        xor, (.&.))
import           Data.ByteString       (ByteString)
import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as C
import           Data.Char             (digitToInt, intToDigit, ord)
import           Data.Either           (isRight)
import           Data.Foldable         (foldlM)
import           Data.List             (elemIndex, find, maximumBy, minimumBy,
                                        nub, unfoldr)
import           Data.Maybe            (fromJust, isJust)
import           Data.Ord              (comparing)
import           Data.Word             (Word8)
import           OpenSSL.Cipher        (Mode (..), aesCBC, newAESCtx)
import           OpenSSL.Random        (randBytes)
import           System.Random         (Random, random, randomIO, randomRIO)
import           Test.HUnit

-- Set 1 • Challenge 1 • Convert hex to base64
--------------------------------------------------------------------------------
chunksOf :: Int -> [a] -> [[a]]
chunksOf n =
  unfoldr
    (\case
       [] -> Nothing
       x -> Just $ splitAt n x)

decodeHex :: ByteString -> ByteString
decodeHex =
  B.pack .
  map (\[x, y] -> fromIntegral $ shiftL (digitToInt x) 4 + digitToInt y) .
  chunksOf 2 . C.unpack

encodeHex :: ByteString -> ByteString
encodeHex =
  C.pack .
  map (intToDigit . fromIntegral) .
  concatMap (\w -> [shiftR (w .&. 0xf0) 4, w .&. 0x0f]) . B.unpack

base64Chars :: String
base64Chars = ['A' .. 'Z'] <> ['a' .. 'z'] <> ['0' .. '9'] <> ['+', '/']

-- Explode a word of length n in to n (Bool) bits
explodeBits :: Bits a => Int -> a -> [Bool]
explodeBits n word = map (testBit word) [n - 1,n - 2 .. 0]

-- Collapse (Bool) bits in to a word of length n
collapseBits :: (Bits a, Num a) => Int -> [Bool] -> a
collapseBits n =
  sum . map fst . filter snd . zip [2 ^ p | p <- [n - 1,n - 2 .. 0]]

decodeBase64 :: ByteString -> ByteString
decodeBase64 =
  B.pack .
  map (collapseBits 8) .
  filter ((== 8) . length) .
  chunksOf 8 .
  concatMap (\c -> explodeBits 6 . fromJust . elemIndex c $ base64Chars) .
  filter (`elem` base64Chars) . C.unpack

encodeBase64 :: ByteString -> ByteString
encodeBase64 =
  C.pack .
  pad .
  map ((base64Chars !!) . collapseBits 6) .
  chunksOf 6 . concatMap (explodeBits 8) . B.unpack
  where
    pad x
      | length x `mod` 4 == 3 = x <> "="
      | length x `mod` 4 == 2 = x <> "=="
      | otherwise = x

testBase64Padding :: Test
testBase64Padding =
  TestCase $ do
    encodeBase64 "any carnal pleasure." @?= "YW55IGNhcm5hbCBwbGVhc3VyZS4="
    encodeBase64 "any carnal pleasure" @?= "YW55IGNhcm5hbCBwbGVhc3VyZQ=="
    encodeBase64 "any carnal pleasur" @?= "YW55IGNhcm5hbCBwbGVhc3Vy"
    decodeBase64 "YW55IGNhcm5hbCBwbGVhc3Vy" @?= "any carnal pleasur"
    decodeBase64 "YW55IGNhcm5hbCBwbGVhc3VyZQ==" @?= "any carnal pleasure"
    decodeBase64 "YW55IGNhcm5hbCBwbGVhc3VyZS4=" @?= "any carnal pleasure."

challenge1 :: Test
challenge1 = TestCase $ (encodeBase64 . decodeHex $ hex) @?= base64
  where
    hex =
      "49276d206b696c6c696e6720796f757220627261696e206c" <>
      "696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

-- Set 1 • Challenge 2 • Fixed XOR
--------------------------------------------------------------------------------
(.+.) :: ByteString -> ByteString -> ByteString
a .+. b
  | B.length a >= B.length b = B.pack $ zipWith xor (B.unpack a) (B.unpack b')
  | otherwise = b .+. a
  where
    b' = B.pack (replicate (B.length a - B.length b) 0) <> b

challenge2 :: Test
challenge2 =
  TestCase $
  encodeHex
    (decodeHex "1c0111001f010100061a024b53535009181c" .+.
     decodeHex "686974207468652062756c6c277320657965") @?=
  "746865206b696420646f6e277420706c6179"

-- Set 1 • Challenge 3 • Single-byte XOR cipher
--------------------------------------------------------------------------------
-- Counting spaces is not the most sophisticated scoring method but is good
-- enough here.
countSpaces :: ByteString -> Int
countSpaces = length . filter (== (fromIntegral . ord $ ' ')) . B.unpack

breakSingleByteXOR :: ByteString -> (Word8, ByteString)
breakSingleByteXOR ciphertext =
  (key, ciphertext .+. B.pack (replicate (B.length ciphertext) key))
  where
    key =
      maximumBy
        (comparing
           (\k ->
              countSpaces $
              ciphertext .+. B.pack (replicate (B.length ciphertext) k)))
        [0 .. 255]

challenge3 :: Test
challenge3 =
  TestCase $ do
    B.pack [key] @?= "X"
    plaintext @?= "Cooking MC's like a pound of bacon"
  where
    (key, plaintext) =
      breakSingleByteXOR . decodeHex $
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

-- Set 1 • Challenge 4 • Detect single-character XOR
--------------------------------------------------------------------------------
-- Apply our break to every ciphertext and return the highest scoring.
detectSingleByteXOR :: [ByteString] -> ByteString
detectSingleByteXOR =
  maximumBy (comparing $ countSpaces . snd . breakSingleByteXOR)

challenge4 :: Test
challenge4 =
  TestCase $ do
    ciphertexts <- map decodeHex . C.lines <$> B.readFile "data/4.txt"
    let (key, plaintext) =
          breakSingleByteXOR . detectSingleByteXOR $ ciphertexts
    B.pack [key] @?= "5"
    plaintext @?= "Now that the party is jumping\n"

-- Set 1 • Challenge 5 • Implement repeating-key XOR
--------------------------------------------------------------------------------
encryptRepeatingKeyXOR :: ByteString -> ByteString -> ByteString
encryptRepeatingKeyXOR key plaintext =
  plaintext .+.
  B.take
    (B.length plaintext)
    (mconcat (replicate (B.length plaintext `div` B.length key + 1) key))

challenge5 :: Test
challenge5 =
  TestCase $ encodeHex (encryptRepeatingKeyXOR key plaintext) @?= ciphertext
  where
    plaintext =
      "Burning 'em, if you ain't quick and nimble\n" <>
      "I go crazy when I hear a cymbal"
    key = "ICE"
    ciphertext =
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623" <>
      "d63343c2a26226324272765272a282b2f20430a652e2c652a" <>
      "3124333a653e2b2027630c692b20283165286326302e27282f"

-- Set 1 • Challenge 6 • Break repeating-key XOR
--------------------------------------------------------------------------------
hammingDistance :: ByteString -> ByteString -> Int
hammingDistance a b = sum . map popCount . B.unpack $ a .+. b

testHammingDistance :: Test
testHammingDistance =
  TestCase $ hammingDistance "this is a test" "wokka wokka!!!" @?= 37

blocksOf :: Int -> ByteString -> [ByteString]
blocksOf n =
  unfoldr
    (\case
       "" -> Nothing
       s -> Just $ C.splitAt n s)

windowsOf :: Int -> [a] -> [[a]]
windowsOf n =
  unfoldr
    (\xs ->
       if length xs < n
         then Nothing
         else Just (take n xs, tail xs))

mean :: (Foldable t, Fractional a) => t a -> a
mean xs = sum xs / fromIntegral (length xs)

likelyKeysize :: ByteString -> Int
likelyKeysize ciphertext =
  minimumBy
    (comparing $ \keysize ->
       mean .
       map
         (\[a, b] -> fromIntegral (hammingDistance a b) / fromIntegral keysize) .
       windowsOf 2 . blocksOf keysize $
       ciphertext)
    [2 .. 40]

breakRepeatingKeyXOR :: ByteString -> (ByteString, ByteString)
breakRepeatingKeyXOR ciphertext = (key, plaintext)
  where
    key = B.pack . map fst $ fragments
    plaintext = mconcat . C.transpose . map snd $ fragments
    fragments =
      map breakSingleByteXOR . C.transpose . blocksOf keysize $ ciphertext
    keysize = likelyKeysize ciphertext

playThatFunkyMusic :: ByteString
playThatFunkyMusic =
  C.unlines
    [ "I'm back and I'm ringin' the bell "
    , "A rockin' on the mike while the fly girls yell "
    , "In ecstasy in the back of me "
    , "Well that's my DJ Deshay cuttin' all them Z's "
    , "Hittin' hard and the girlies goin' crazy "
    , "Vanilla's on the mike, man I'm not lazy. "
    , ""
    , "I'm lettin' my drug kick in "
    , "It controls my mouth and I begin "
    , "To just let it flow, let my concepts go "
    , "My posse's to the side yellin', Go Vanilla Go! "
    , ""
    , "Smooth 'cause that's the way I will be "
    , "And if you don't give a damn, then "
    , "Why you starin' at me "
    , "So get off 'cause I control the stage "
    , "There's no dissin' allowed "
    , "I'm in my own phase "
    , "The girlies sa y they love me and that is ok "
    , "And I can dance better than any kid n' play "
    , ""
    , "Stage 2 -- Yea the one ya' wanna listen to "
    , "It's off my head so let the beat play through "
    , "So I can funk it up and make it sound good "
    , "1-2-3 Yo -- Knock on some wood "
    , "For good luck, I like my rhymes atrocious "
    , "Supercalafragilisticexpialidocious "
    , "I'm an effect and that you can bet "
    , "I can take a fly girl and make her wet. "
    , ""
    , "I'm like Samson -- Samson to Delilah "
    , "There's no denyin', You can try to hang "
    , "But you'll keep tryin' to get my style "
    , "Over and over, practice makes perfect "
    , "But not if you're a loafer. "
    , ""
    , "You'll get nowhere, no place, no time, no girls "
    , "Soon -- Oh my God, homebody, you probably eat "
    , "Spaghetti with a spoon! Come on and say it! "
    , ""
    , "VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino "
    , "Intoxicating so you stagger like a wino "
    , "So punks stop trying and girl stop cryin' "
    , "Vanilla Ice is sellin' and you people are buyin' "
    , "'Cause why the freaks are jockin' like Crazy Glue "
    , "Movin' and groovin' trying to sing along "
    , "All through the ghetto groovin' this here song "
    , "Now you're amazed by the VIP posse. "
    , ""
    , "Steppin' so hard like a German Nazi "
    , "Startled by the bases hittin' ground "
    , "There's no trippin' on mine, I'm just gettin' down "
    , "Sparkamatic, I'm hangin' tight like a fanatic "
    , "You trapped me once and I thought that "
    , "You might have it "
    , "So step down and lend me your ear "
    , "'89 in my time! You, '90 is my year. "
    , ""
    , "You're weakenin' fast, YO! and I can tell it "
    , "Your body's gettin' hot, so, so I can smell it "
    , "So don't be mad and don't be sad "
    , "'Cause the lyrics belong to ICE, You can call me Dad "
    , "You're pitchin' a fit, so step back and endure "
    , "Let the witch doctor, Ice, do the dance to cure "
    , "So come up close and don't be square "
    , "You wanna battle me -- Anytime, anywhere "
    , ""
    , "You thought that I was weak, Boy, you're dead wrong "
    , "So come on, everybody and sing this song "
    , ""
    , "Say -- Play that funky music Say, go white boy, go white boy go "
    , "play that funky music Go white boy, go white boy, go "
    , "Lay down and boogie and play that funky music till you die. "
    , ""
    , "Play that funky music Come on, Come on, let me hear "
    , "Play that funky music white boy you say it, say it "
    , "Play that funky music A little louder now "
    , "Play that funky music, white boy Come on, Come on, Come on "
    , "Play that funky music "
    ]

challenge6 :: Test
challenge6 =
  TestCase $ do
    ciphertext <- decodeBase64 <$> B.readFile "data/6.txt"
    let (key, plaintext) = breakRepeatingKeyXOR ciphertext
    key @?= "Terminator X: Bring the noise"
    plaintext @?= playThatFunkyMusic

-- Set 1 • Challenge 7 • AES in ECB mode
--------------------------------------------------------------------------------
blockCipher :: Mode -> ByteString -> ByteString -> IO ByteString
blockCipher mode key block
  | B.length block /= 16 = fail "block must be 16 bytes long"
  | otherwise = do
    ctx <- newAESCtx mode key (B.pack $ replicate 16 0)
    aesCBC ctx block

encryptECB :: ByteString -> ByteString -> IO ByteString
encryptECB key = foldlM step "" . blocksOf 16 . padPKCS7 16
  where
    step ciphertext block = do
      c <- blockCipher Encrypt key block
      return $ ciphertext <> c

decryptECB ::
     ByteString -> ByteString -> IO (Either InvalidPaddingError ByteString)
decryptECB key = fmap unpadPKCS7 . foldlM step "" . blocksOf 16
  where
    step plaintext block = do
      p <- blockCipher Decrypt key block
      return $ plaintext <> p

challenge7 :: Test
challenge7 =
  TestCase $ do
    ciphertext <- decodeBase64 <$> B.readFile "data/7.txt"
    Right plaintext <- decryptECB "YELLOW SUBMARINE" ciphertext
    plaintext @?= playThatFunkyMusic

-- Set 1 • Challenge 8 • Detect AES in ECB mode
--------------------------------------------------------------------------------
countRepeatingBlocks :: ByteString -> Int
countRepeatingBlocks ciphertext = length blocks - length (nub blocks)
  where
    blocks = blocksOf 16 ciphertext

detectECB :: [ByteString] -> ByteString
detectECB = maximumBy $ comparing countRepeatingBlocks

challenge8 :: Test
challenge8 =
  TestCase $ do
    ciphertexts <- map decodeHex . C.lines <$> B.readFile "data/8.txt"
    -- Not confirmed to be correct, so test is only useful to know if I
    -- accidentally change anything.
    encodeHex (detectECB ciphertexts) @?=
      "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283" <>
      "e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd283" <>
      "9475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd283" <>
      "97a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283" <>
      "d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"

-- Set 2 • Challenge 9 • Implement PKCS#7 padding
--------------------------------------------------------------------------------
padPKCS7 :: Int -> ByteString -> ByteString
padPKCS7 blockSize text = text <> B.pack (replicate n $ fromIntegral n)
  where
    n = blockSize - B.length text `mod` blockSize

data InvalidPaddingError =
  InvalidPaddingError
  deriving (Eq, Ord, Show)

unpadPKCS7 :: ByteString -> Either InvalidPaddingError ByteString
unpadPKCS7 text
  | isValid = Right $ B.take (B.length text - padLength) text
  | otherwise = Left InvalidPaddingError
  where
    padLength = fromIntegral $ B.last text
    isValid =
      B.drop (B.length text - padLength) text ==
      B.pack (replicate padLength (fromIntegral padLength))

challenge9 :: Test
challenge9 =
  TestCase $
  padPKCS7 20 "YELLOW SUBMARINE" @?= "YELLOW SUBMARINE\x04\x04\x04\x04"

-- Set 2 • Challenge 10 • Implement CBC mode
--------------------------------------------------------------------------------
encryptCBC :: ByteString -> ByteString -> ByteString -> IO ByteString
encryptCBC key iv = fmap fst . foldlM step ("", iv) . blocksOf 16 . padPKCS7 16
  where
    step (ciphertext, chained) block = do
      block' <- blockCipher Encrypt key (block .+. chained)
      return (ciphertext <> block', block')

decryptCBC ::
     ByteString
  -> ByteString
  -> ByteString
  -> IO (Either InvalidPaddingError ByteString)
decryptCBC key iv = fmap (unpadPKCS7 . fst) . foldlM step ("", iv) . blocksOf 16
  where
    step (plaintext, chained) block = do
      block' <- blockCipher Decrypt key block
      return (plaintext <> block' .+. chained, block)

challenge10 :: Test
challenge10 =
  TestCase $ do
    ciphertext <- decodeBase64 <$> B.readFile "data/10.txt"
    Right plaintext <-
      decryptCBC "YELLOW SUBMARINE" (B.pack $ replicate 16 0) ciphertext
    plaintext @?= playThatFunkyMusic

-- Set 2 • Challenge 11 • An ECB/CBC detection oracle
--------------------------------------------------------------------------------
data ModeOfOperation
  = ECB
  | CBC
  deriving (Eq, Ord, Show)

instance Random ModeOfOperation where
  random g
    | b = (ECB, g')
    | otherwise = (CBC, g')
    where
      (b, g') = random g

oracle11 :: ModeOfOperation -> ByteString -> IO ByteString
oracle11 mode plaintext = do
  key <- randBytes 16
  prefix <- randBytes =<< randomRIO (5, 10)
  suffix <- randBytes =<< randomRIO (5, 10)
  case mode of
    ECB -> encryptECB key (prefix <> plaintext <> suffix)
    CBC -> do
      iv <- randBytes 16
      encryptCBC key iv (prefix <> plaintext <> suffix)

-- If we feed the oracle three blocks of 0s, then after up to a whole block of
-- padding, the second and third block of plaintext will still be all 0s, and
-- thus under ECB will produce the same ciphertext.
detectMode :: (ByteString -> IO ByteString) -> IO ModeOfOperation
detectMode oracle = do
  ciphertext <- oracle . B.pack $ replicate 48 0
  let blocks = blocksOf 16 ciphertext
  if blocks !! 1 == blocks !! 2
    then return ECB
    else return CBC

challenge11 :: Test
challenge11 =
  TestCase . replicateM_ 100 $ do
    mode <- randomIO
    detectedMode <- detectMode $ oracle11 mode
    detectedMode @?= mode

-- Set 2 • Challenge 12 • Byte-at-a-time ECB decryption (Simple)
--------------------------------------------------------------------------------
findM :: (Monad m, Foldable f) => (a -> m Bool) -> f a -> m (Maybe a)
findM p = foldr go (return Nothing)
  where
    go x acc = do
      b <- p x
      if b
        then return $ Just x
        else acc

detectBlockSize :: (ByteString -> IO ByteString) -> Int -> Maybe Int -> IO Int
detectBlockSize oracle n lastSize = do
  size <- fmap B.length . oracle . B.pack $ replicate n 0
  if isJust lastSize && Just size /= lastSize
    then return $ size - fromJust lastSize
    else detectBlockSize oracle (n + 1) (Just size)

breakECBSimple :: (ByteString -> IO ByteString) -> IO ByteString
breakECBSimple oracle = do
  blockSize <- detectBlockSize oracle 0 Nothing
  when (blockSize /= 16) $ fail "expected block size of 16"
  mode <- detectMode oracle
  when (mode /= ECB) $ fail "expected ECB"
  ciphertextLength <- B.length <$> oracle ""
  go ciphertextLength ""
  where
    go ciphertextLength plaintext
      | B.length plaintext == ciphertextLength = return plaintext
      | otherwise = do
        let padding =
              B.pack $ replicate (ciphertextLength - B.length plaintext - 1) 0
        image <- fmap (B.take ciphertextLength) . oracle $ padding
        preimage <-
          findM
            (fmap ((== image) . B.take ciphertextLength) .
             oracle . B.snoc (padding <> plaintext))
            [0 .. 255]
        case preimage of
          Just preimage' -> go ciphertextLength (B.snoc plaintext preimage')
          Nothing
            -- There's no preimage, which indicates that we've finished
            -- breaking the secret, and the oracle is now appending padding
            -- bytes which are changing beneath us. If this is true, the last
            -- byte we added will have been 1 (for one byte of padding) and now
            -- will have changed to 2. Let's make some assertions to confirm
            -- our understanding of the situation and then we're done.
           -> do
            when (B.last plaintext /= 1) $ fail "expected 1 byte of padding"
            prediction <-
              liftA2
                (==)
                (fmap (B.take ciphertextLength) . oracle $
                 padding <> B.take (B.length plaintext - 1) plaintext <> "\2\2")
                (oracle padding)
            unless prediction $ fail "expected padding prediction to hold"
            return $ B.take (B.length plaintext - 1) plaintext

challenge12 :: Test
challenge12 =
  TestCase $ do
    let secret =
          decodeBase64 $
          "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIG" <>
          "Rvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll" <>
          "cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQ" <>
          "pEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    key <- randBytes 16
    brokenSecret <-
      breakECBSimple $ \plaintext -> encryptECB key (plaintext <> secret)
    brokenSecret @?= secret
    brokenSecret @?=
      C.unlines
        [ "Rollin' in my 5.0"
        , "With my rag-top down so my hair can blow"
        , "The girlies on standby waving just to say hi"
        , "Did you stop? No, I just drove by"
        ]

-- Set 2 • Challenge 13 • ECB cut-and-paste
--------------------------------------------------------------------------------
decodeKeyValue :: Char -> ByteString -> [(ByteString, ByteString)]
decodeKeyValue sep = map ((\[k, v] -> (k, v)) . C.split '=') . C.split sep

-- Only encodes '&', ';', and '=' since that's all we need for the problems.
-- Encodings taken from https://en.wikipedia.org/wiki/Percent-encoding.
percentEncode :: ByteString -> ByteString
percentEncode =
  C.concatMap
    (\case
       '&' -> "%26"
       ';' -> "%3B"
       '=' -> "%3D"
       c -> C.pack [c])

-- sep should be one of '&' or ';' so that it is properly escaped.
encodeKeyValue :: Char -> [(ByteString, ByteString)] -> ByteString
encodeKeyValue sep =
  B.intercalate (C.pack [sep]) .
  map (\(k, v) -> percentEncode k <> "=" <> percentEncode v)

testKeyValue :: Test
testKeyValue =
  TestCase $ do
    decodeKeyValue '&' "foo=bar&baz=qux&zap=zazzle" @?=
      [("foo", "bar"), ("baz", "qux"), ("zap", "zazzle")]
    encodeKeyValue '&' [("foo", "bar"), ("baz", "qux"), ("zap", "zazzle")] @?=
      "foo=bar&baz=qux&zap=zazzle"
    encodeKeyValue '&' [("em&=ail", "foo@bar&role=admin")] @?=
      "em%26%3Dail=foo@bar%26role%3Dadmin"

-- Feed the oracle an email which will result in it encryping two blocks which
-- look like:
--
--     "email=<padding>" "admin<padding>" <other stuff we don't care about>
--
-- Now feed an email which causes the role value to appear at the start of the
-- third block.
--
--     "email=<padding>" "<padding>&uid=10&role=" "user<padding>"
--
-- Now we can swap out the last block of ciphertext for our fake admin block.
spoofAdminTokenECB :: (ByteString -> IO ByteString) -> IO ByteString
spoofAdminTokenECB oracle = do
  fakeAdminBlock <-
    fmap ((!! 1) . blocksOf 16) . oracle $
    pad (16 - B.length "email=") 'X' <> padPKCS7 16 "admin"
  userToken <-
    oracle $ pad (32 - B.length "email=" - B.length "&uid=10&role=") 'X'
  return $ B.take 32 userToken <> fakeAdminBlock
  where
    pad n c = C.pack $ replicate n c

challenge13 :: Test
challenge13 =
  TestCase $ do
    key <- randBytes 16
    adminToken <-
      spoofAdminTokenECB $ \email ->
        encryptECB
          key
          (encodeKeyValue
             '&'
             [("email", email), ("uid", "10"), ("role", "user")])
    Right adminProfile <-
      fmap (decodeKeyValue '&') <$> decryptECB key adminToken
    adminProfile @?=
      [("email", "XXXXXXXXXXXXX"), ("uid", "10"), ("role", "admin")]

-- Set 2 • Challenge 14 • Byte-at-a-time ECB decryption (Harder)
--------------------------------------------------------------------------------
-- Detect the prefix length by feeding input to the cipher which differs in
-- exactly one byte and comparing the indices of the blocks which differ in the
-- ciphertext. The initial response indicates the block that the padding ends
-- in, and then by shifting the differing bit progressively further to the
-- right we can see how far we have to move it to effect change in the next
-- block, and thus how much of the last block the padding occupies.
detectPrefixLength :: (ByteString -> IO ByteString) -> IO Int
detectPrefixLength oracle = do
  initialResponse <- stimulate 0
  go initialResponse 1
  where
    stimulate n =
      fst . fromJust . find snd . zip [0 ..] <$>
      (liftA2 $ zipWith (/=))
        (fmap (blocksOf 16) . oracle $ pad n <> "0")
        (fmap (blocksOf 16) . oracle $ pad n <> "1")
    pad n = B.pack $ replicate n 0
    go initialResponse n = do
      response <- stimulate n
      if response /= initialResponse
        then return $ response * 16 - n
        else go initialResponse (n + 1)

testDetectPrefixLength :: Test
testDetectPrefixLength =
  TestCase . replicateM_ 100 $ do
    key <- randBytes 16
    prefix <- randBytes =<< randomRIO (0, 256)
    prefixLength <-
      detectPrefixLength $ \plaintext -> encryptECB key (prefix <> plaintext)
    prefixLength @?= B.length prefix

-- Once we've detected the prefix length we can pad the prefix up to a whole
-- number of blocks, drop them from the ciphertext and proceed as in
-- breakECBSimple.
breakECBHarder :: (ByteString -> IO ByteString) -> IO ByteString
breakECBHarder oracle = do
  prefixLength <- detectPrefixLength oracle
  let prefixPaddingLength = 16 - prefixLength `mod` 16
  breakECBSimple $ \plaintext ->
    B.drop (prefixLength + prefixPaddingLength) <$>
    oracle (B.pack (replicate prefixPaddingLength 0) <> plaintext)

challenge14 :: Test
challenge14 =
  TestCase $ do
    let secret =
          decodeBase64 $
          "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIG" <>
          "Rvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll" <>
          "cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQ" <>
          "pEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    key <- randBytes 16
    -- The problem doesn't state a range for number of bytes, so I'm going to
    -- err on the side of "lots".
    prefix <- randBytes =<< randomRIO (0, 256)
    brokenSecret <-
      breakECBHarder $ \plaintext ->
        encryptECB key (prefix <> plaintext <> secret)
    brokenSecret @?= secret
    brokenSecret @?=
      C.unlines
        [ "Rollin' in my 5.0"
        , "With my rag-top down so my hair can blow"
        , "The girlies on standby waving just to say hi"
        , "Did you stop? No, I just drove by"
        ]

-- Set 2 • Challenge 15 • PKCS#7 padding validation
--------------------------------------------------------------------------------
challenge15 :: Test
challenge15 =
  TestCase $ do
    unpadPKCS7 "ICE ICE BABY\x04\x04\x04\x04" @?= Right "ICE ICE BABY"
    unpadPKCS7 "ICE ICE BABY\x05\x05\x05\x05" @?= Left InvalidPaddingError
    unpadPKCS7 "ICE ICE BABY\x01\x02\x03\x04" @?= Left InvalidPaddingError

-- Set 2 • Challenge 16 • CBC bitflipping attacks
--------------------------------------------------------------------------------
isAdmin :: ByteString -> ByteString -> ByteString -> IO Bool
isAdmin key iv =
  fmap (either (const False) (elem ("admin", "true") . decodeKeyValue ';')) .
  decryptCBC key iv

-- Choose userdata so that our plaintext looks like
--
--     "comment1=cooking" "%20MCs;userdata=" "XXXXXXXXXXXXXXXX"
--     "XXXXXXXXXXXXXXXX" ";comment2=%20lik" "e%20a%20pound%20"
--     "of%20bacon"
--
-- Then we can flip bits in the third block of ciphertext to produce the
-- desired change in the fourth block of plaintext. The oracle should only be
-- called once in this function.
spoofAdminTokenCBC :: (ByteString -> IO ByteString) -> IO ByteString
spoofAdminTokenCBC oracle = do
  let userdata = C.pack $ replicate 32 'X'
  (t0:t1:t2:ts) <- blocksOf 16 <$> oracle userdata
  return . B.concat $
    t0 : t1 : t2 .+. "XXXXXXXXXXXXXXXX" .+. "XXXXX;admin=true" : ts

challenge16 :: Test
challenge16 =
  TestCase $ do
    key <- randBytes 16
    iv <- randBytes 16
    adminToken <-
      spoofAdminTokenCBC
        (\userdata ->
           encryptCBC key iv $
           "comment1=cooking%20MCs;userdata=" <>
           userdata <> ";comment2=%20like%20a%20pound%20of%20bacon")
    a <- isAdmin key iv adminToken
    a @?= True

-- Set 3 • Challenge 17 • The CBC padding oracle
--------------------------------------------------------------------------------
-- See https://en.wikipedia.org/wiki/Padding_oracle_attack and
-- https://robertheaton.com/2013/07/29/padding-oracle-attack/
--
-- TODO This occasionally seems to hit a worst case scenario where every byte
-- gives us the correct padding, exploding the search space. It would be nice
-- to figure out when that happens and why.
cbcPaddingOracleAttack ::
     (ByteString -> IO Bool)
  -> ByteString
  -> IO (Either InvalidPaddingError ByteString)
cbcPaddingOracleAttack paddingOracle =
  fmap (unpadPKCS7 . mconcat) .
  mapM (\[c1, c2] -> head <$> attackBlock "" c1 c2) . windowsOf 2 . blocksOf 16
  where
    attackBlock i2 c1 c2
      | B.length i2 == 16 = return [i2 .+. c1]
      | otherwise = do
        let targetIndex = 15 - B.length i2
        let paddingByte = fromIntegral $ 16 - targetIndex
        hits <-
          filterM
            (\b -> do
               noise <- randBytes targetIndex
               let c1' =
                     noise <>
                     B.singleton b <> (i2 .+. bytes (B.length i2) paddingByte)
               paddingOracle (c1' <> c2))
            [0 .. 255]
        concat <$>
          mapM
            (\hit -> attackBlock ((hit `xor` paddingByte) `B.cons` i2) c1 c2)
            hits
    bytes n = B.pack . replicate n

challenge17 :: Test
challenge17 = TestCase . mapM_ (go . decodeBase64) $ secrets
  where
    go secret = do
      key <- randBytes 16
      iv <- randBytes 16
      ciphertext <- encryptCBC key iv secret
      Right brokenSecret <-
        cbcPaddingOracleAttack (paddingOracle key iv) (iv <> ciphertext)
      brokenSecret @?= secret
    paddingOracle key iv = fmap isRight . decryptCBC key iv
    secrets =
      [ "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
      , "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW" <>
        "4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
      , "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
      , "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
      , "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
      , "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
      , "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
      , "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
      , "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
      , "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
      ]

--------------------------------------------------------------------------------
main :: IO ()
main =
  void . runTestTT $
  TestList
    [ testBase64Padding
    , testHammingDistance
    , testKeyValue
    , testDetectPrefixLength
    , challenge1
    , challenge2
    , challenge3
    , challenge4
    , challenge5
    , challenge6
    , challenge7
    , challenge8
    , challenge9
    , challenge10
    , challenge11
    , challenge12
    , challenge13
    , challenge14
    , challenge15
    , challenge16
    , challenge17
    ]
