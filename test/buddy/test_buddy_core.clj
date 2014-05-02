(ns buddy.test_buddy_core
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.core.keys :refer :all]
            [buddy.core.hash :as hash]
            [buddy.core.hmac :refer [shmac-sha256]]
            [buddy.hashers.pbkdf2 :as pbkdf2]
            [buddy.hashers.bcrypt :as bcrypt]
            [buddy.hashers.sha256 :as sha256]
            [buddy.hashers.md5 :as md5]
            [buddy.hashers.scrypt :as scrypt]
            [buddy.core.mac.poly1305 :as poly]
            [buddy.core.crypto.chacha :as chacha]
            [buddy.core.kdf :as kdf]
            [clojure.java.io :as io])
  (:import buddy.Arrays))

(deftest buddy-core-codecs
  (testing "Hex encode/decode 01"
    (let [some-bytes  (str->bytes "FooBar")
          encoded     (bytes->hex some-bytes)
          decoded     (hex->bytes encoded)
          some-str    (bytes->str decoded)]
      (is (Arrays/equals decoded, some-bytes))
      (is (= some-str "FooBar"))))

  (testing "Hex encode/decode 02"
    (let [mybytes (into-array Byte/TYPE (range 10))
          encoded (bytes->hex mybytes)
          decoded (hex->bytes encoded)]
      (is (Arrays/equals decoded mybytes)))))

(deftest buddy-hashers
  (testing "Test low level api for encrypt/verify pbkdf2"
    (let [plain-password      "my-test-password"
          encrypted-password  (pbkdf2/make-password plain-password)]
      (is (pbkdf2/check-password plain-password encrypted-password))))

  (testing "Test low level api for encrypt/verify sha256"
    (let [plain-password      "my-test-password"
          encrypted-password  (sha256/make-password plain-password)]
      (is (sha256/check-password plain-password encrypted-password))))

  (testing "Test low level api for encrypt/verify md5"
    (let [plain-password      "my-test-password"
          encrypted-password  (md5/make-password plain-password)]
      (is (md5/check-password plain-password encrypted-password))))

  (testing "Test low level api for encrypt/verify bcrypt"
    (let [plain-password      "my-test-password"
          encrypted-password  (bcrypt/make-password plain-password)]
      (is (bcrypt/check-password plain-password encrypted-password))))

  (testing "Test low level api for encrypt/verify scrypt"
    (let [plain-password      "my-test-password"
          encrypted-password  (scrypt/make-password plain-password)]
      (is (scrypt/check-password plain-password encrypted-password)))))

(deftest buddy-core-hash
  (testing "SHA3 support test"
    (let [plain-text "FooBar"
          hashed     (-> (hash/sha3-256 plain-text)
                         (bytes->hex))]
      (is (= hashed "0a3c119a02a37e50fbaf8a3776559c76de7a969097c05bd0f41f60cf25210745"))))
  (testing "File hashing"
    (let [path       "test/_files/pubkey.ecdsa.pem"
          valid-hash "7aa01e35e65701c9a9d8f71c4cbf056acddc9be17fdff06b4c7af1b0b34ddc29"]
      (is (= (bytes->hex (hash/sha256 (io/input-stream path))) valid-hash)))))

(deftest buddy-core-codecs
  (testing "Safe base64 encode/decode"
    (let [output1 (str->safebase64 "foo")
          output2 (safebase64->str output1)]
      (is (= output1 "Zm9v"))
      (is (= output2 "foo")))))

(deftest buddy-core-mac-poly1305
  (let [iv        (byte-array 16) ;; 16 bytes array filled with 0
        plaintext "text"
        secretkey "secret"]
    (testing "Poly1305 encrypt/verify (using string key)"
      (let [mac-bytes1 (poly/poly1305 plaintext secretkey iv :aes)
            mac-bytes2 (poly/poly1305 plaintext secretkey iv :aes)]
      (is (= (Arrays/equals mac-bytes1 mac-bytes2)))))

  (testing "Poly1305 explicit encrypt/verify (using string key)"
    (let [mac-bytes1 (poly/poly1305 plaintext secretkey iv :aes)]
      (is (= (-> mac-bytes1 (bytes->hex)) "98a94ff88861bf9b96bcb7112b506579"))))

  (testing "File mac"
    (let [path       "test/_files/pubkey.ecdsa.pem"
          macbytes   (poly/poly1305 (io/input-stream path) secretkey iv :aes)]
      (is (poly/poly1305-verify (io/input-stream path) macbytes secretkey iv :aes))))

  (testing "Poly1305-AES enc/verify using key with good iv"
    (let [iv1      (make-random-bytes 16)
          iv2      (make-random-bytes 16)
          macbytes1 (poly/poly1305 plaintext secretkey iv1 :aes)
          macbytes2 (poly/poly1305-aes plaintext secretkey iv1)]
      (is (poly/poly1305-verify plaintext macbytes1 secretkey iv1 :aes))
      (is (poly/poly1305-aes-verify plaintext macbytes2 secretkey iv1))
      (is (not (poly/poly1305-verify plaintext macbytes1 secretkey iv2 :aes)))))

  (testing "Poly1305-Twofish env/verify"
    (let [iv2 (make-random-bytes 16)
          signature (poly/poly1305-twofish plaintext secretkey iv2)]
      (is (poly/poly1305-twofish-verify plaintext signature secretkey iv2))
      (is (not (poly/poly1305-twofish-verify plaintext signature secretkey iv)))))

  (testing "Poly1305-Serpent env/verify"
    (let [iv2 (make-random-bytes 16)
          signature (poly/poly1305-serpent plaintext secretkey iv2)]
      (is (poly/poly1305-serpent-verify plaintext signature secretkey iv2))
      (is (not (poly/poly1305-serpent-verify plaintext signature secretkey iv)))))))

(deftest buddy-core-crypto-chacha
  (let [iv1    (make-random-bytes 8)
        iv2    (make-random-bytes 8)
        key1   (make-random-bytes 32)
        key2   (make-random-bytes 16)
        plain1 (make-random-bytes 100)]
    (testing "Enc/Dec simple text"
      (let [encrypted (chacha/encrypt plain1 key1 iv1)]
        (is (Arrays/equals plain1 (chacha/decrypt encrypted key1 iv1)))
        (is (not (Arrays/equals plain1 (chacha/decrypt encrypted key1 iv2))))
        (is (not (Arrays/equals plain1 (chacha/decrypt encrypted key2 iv1))))))))

(deftest buddy-core-kdf
  (let [key1 (make-random-bytes 32)
        key2 (make-random-bytes 16)
        salt (make-random-bytes 8)
        info (make-random-bytes 8)]
    (testing "HKDF with sha256 with info"
      (let [generator1 (kdf/hkdf key1 salt info :sha256)
            generator2 (kdf/hkdf key1 salt info :sha256)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)
            bytes3     (kdf/generate-bytes! generator1 8)
            bytes4     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes3 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes4 (kdf/generate-bytes! generator2 8)))))
    (testing "HKDF with sha256 without info"
      (let [generator1 (kdf/hkdf key1 salt nil :sha256)
            generator2 (kdf/hkdf key1 salt nil :sha256)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))))

    (testing "KDF1 with sha512"
      (let [generator1 (kdf/kdf1 key1 salt :sha512)
            generator2 (kdf/kdf1 key1 salt :sha512)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)
            bytes3     (kdf/generate-bytes! generator1 8)
            bytes4     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes3 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes4 (kdf/generate-bytes! generator2 8)))))

    (testing "KDF2 with sha512"
      (let [generator1 (kdf/kdf2 key1 salt :sha512)
            generator2 (kdf/kdf2 key1 salt :sha512)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)
            bytes3     (kdf/generate-bytes! generator1 8)
            bytes4     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes3 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes4 (kdf/generate-bytes! generator2 8)))))

    (testing "CMKDF with sha3-512"
      (let [generator1 (kdf/cmkdf key1 salt :sha3-512)
            generator2 (kdf/cmkdf key1 salt :sha3-512)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)
            bytes3     (kdf/generate-bytes! generator1 8)
            bytes4     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes3 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes4 (kdf/generate-bytes! generator2 8)))))

    (testing "FMKDF with tiger"
      (let [generator1 (kdf/fmkdf key1 salt :tiger)
            generator2 (kdf/fmkdf key1 salt :tiger)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)
            bytes3     (kdf/generate-bytes! generator1 8)
            bytes4     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes3 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes4 (kdf/generate-bytes! generator2 8)))))

    (testing "DPIMKDF with sha3-256"
      (let [generator1 (kdf/dpimkdf key1 salt :sha3-256)
            generator2 (kdf/dpimkdf key1 salt :sha3-256)
            bytes1     (kdf/generate-bytes! generator1 8)
            bytes2     (kdf/generate-bytes! generator1 8)
            bytes3     (kdf/generate-bytes! generator1 8)
            bytes4     (kdf/generate-bytes! generator1 8)]
        (is (Arrays/equals bytes1 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes2 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes3 (kdf/generate-bytes! generator2 8)))
        (is (Arrays/equals bytes4 (kdf/generate-bytes! generator2 8)))))

))

