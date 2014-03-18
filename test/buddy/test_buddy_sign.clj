(ns buddy.test_buddy_sign
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.sign.generic :as gsign]
            [buddy.core.keys :refer :all]))

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
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey))))
  (testing "Read ec pub key"
    (let [pkey (public-key "test/_files/pubkey.ecdsa.pem")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey)))))


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

