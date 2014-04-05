(ns buddy.test_buddy_sign
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.core.sign :as sign]
            [buddy.sign.generic :as gsign]
            [buddy.core.keys :refer :all]
            [clojure.java.io :as io])
  (:import java.util.Arrays))

(def secret "test")

(deftest rsa-dsa-keys-test
  (testing "Read rsa priv key"
    (let [pkey (private-key "test/_files/privkey.3des.rsa.pem" "secret")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey))))

  (testing "Read dsa priv key"
    (let [pkey (private-key "test/_files/privkey.3des.dsa.pem" "secret")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPrivateKey))))

  (testing "Read rsa priv key with bad password"
    (is (thrown? org.bouncycastle.openssl.EncryptionException
                (private-key "test/_files/privkey.3des.rsa.pem" "secret2"))))

  (testing "Read dsa priv key with bad password"
    (is (thrown? org.bouncycastle.openssl.EncryptionException
                (private-key "test/_files/privkey.3des.dsa.pem" "secret2"))))

  (testing "Read ecdsa priv key"
    (let [pkey (private-key "test/_files/privkey.ecdsa.pem" "secret")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey))))

  (testing "Read rsa pub key"
    (let [pkey (public-key "test/_files/pubkey.3des.rsa.pem")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey))))

  (testing "Read dsa pub key"
    (let [pkey (public-key "test/_files/pubkey.3des.dsa.pem")]
      (is (public-key? pkey))
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey))))

  (testing "Read ec pub key"
    (let [pkey (public-key "test/_files/pubkey.ecdsa.pem")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey)))))


(deftest low-level-sign-tests
  (let [rsa-privkey (private-key "test/_files/privkey.3des.rsa.pem" "secret")
        rsa-pubkey  (public-key "test/_files/pubkey.3des.rsa.pem")
        ec-privkey  (private-key "test/_files/privkey.ecdsa.pem")
        ec-pubkey   (public-key "test/_files/pubkey.ecdsa.pem")]
    (testing "Multiple sign using rsassa-pkcs"
      (is (Arrays/equals (sign/rsassa-pkcs-sha256 "foobar" rsa-privkey)
                         (sign/rsassa-pkcs-sha256 "foobar" rsa-privkey))))

    (testing "Sign/Verify using rsassa-pkcs"
      (let [signature (sign/rsassa-pkcs-sha256 "foobar" rsa-privkey)]
        (is (true? (sign/rsassa-pkcs-sha256-verify "foobar" signature rsa-pubkey)))))

    (testing "Multiple sign using rsassa-pss"
      (is (false? (Arrays/equals (sign/rsassa-pss-sha256 "foobar" rsa-privkey)
                                 (sign/rsassa-pss-sha256 "foobar" rsa-privkey)))))

    (testing "Sign/Verify using rsassa-pss"
      (let [signature (sign/rsassa-pss-sha256 "foobar" rsa-privkey)]
        (is (true? (sign/rsassa-pss-sha256-verify "foobar" signature rsa-pubkey)))))

    (testing "Multiple sign using ecdsa"
      (is (false? (Arrays/equals (sign/ecdsa-sha256 "foobar" ec-privkey)
                                 (sign/ecdsa-sha256 "foobar" ec-privkey)))))

    (testing "Sign/Verify using ecdsa"
      (let [signature (sign/ecdsa-sha256 "foobar" ec-privkey)]
        (is (true? (sign/ecdsa-sha256-verify "foobar" signature ec-pubkey)))))

    (testing "Sign/Verify input stream"
      (let [path "test/_files/pubkey.ecdsa.pem"
            sig  (sign/ecdsa-sha256 (io/input-stream path) ec-privkey)]
        (is (true? (sign/ecdsa-sha256-verify (io/input-stream path) sig ec-pubkey)))))

    (testing "Sign/Verify file"
      (let [path "test/_files/pubkey.ecdsa.pem"
            sig  (sign/ecdsa-sha256 (java.io.File. path) ec-privkey)]
        (is (true? (sign/ecdsa-sha256-verify (java.io.File. path) sig ec-pubkey)))))

    (testing "Sign/Verify url"
      (let [path "test/_files/pubkey.ecdsa.pem"
            sig  (sign/ecdsa-sha256 (.toURL (java.io.File. path)) ec-privkey)]
        (is (true? (sign/ecdsa-sha256-verify (.toURL (java.io.File. path)) sig ec-pubkey)))))

    (testing "Sign/Verify uri"
      (let [path "test/_files/pubkey.ecdsa.pem"
            sig  (sign/ecdsa-sha256 (.toURI (java.io.File. path)) ec-privkey)]
        (is (true? (sign/ecdsa-sha256-verify (.toURI (java.io.File. path)) sig ec-pubkey)))))))

(deftest high-level-sign-tests
  (testing "Signing/Unsigning with default keys"
    (let [signed (gsign/sign "foo" secret)]
      (Thread/sleep 1000)
      (is (not= (gsign/sign "foo" secret) signed))
      (is (= (gsign/unsign signed secret) "foo"))))

  (testing "Signing/Unsigning timestamped"
    (let [signed (gsign/sign "foo" secret)]
      (is (= "foo" (gsign/unsign signed secret {:max-age 20})))
      (Thread/sleep 700)
      (is (nil? (gsign/unsign signed secret {:max-age -1})))))

  (testing "Signing/Unsigning complex clojure data"
    (let [signed (gsign/dumps {:foo 2 :bar 1} secret)]
      (is (= {:foo 2 :bar 1} (gsign/loads signed secret))))))

