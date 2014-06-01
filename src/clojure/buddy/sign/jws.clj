;; Copyright 2014 Andrey Antukh <niwi@niwi.be>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.


;; Links to rfcs:
;; - http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-19
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-25

(ns buddy.sign.jws
  "Json Web Signature implementation."
  (:require [buddy.core.codecs :as codecs]
            [buddy.core.mac.hmac :as hmac]
            [buddy.sign.generic :as gsign]
            [buddy.util :refer [maybe-let]]
            [clj-time.coerce :as jodac]
            [clj-time.core :as jodat]
            [clojure.string :as str]
            [cheshire.core :as json])
  (:import clojure.lang.Keyword))

(defprotocol ITimestamp
  "Default protocol for convert any tipe to
unix timestamp with default implementation for
java.util.Date"
  (to-timestamp [obj] "Covert to timestamp"))

(extend-protocol ITimestamp
  java.util.Date
  (to-timestamp [obj]
    (quot (jodac/to-long obj) 1000))

  org.joda.time.DateTime
  (to-timestamp [obj]
    (quot (jodac/to-long obj) 1000)))

(defn- normalize-date-claims
  "Normalize date related claims and return transformed object."
  [data]
  (into {} (map (fn [[key val]]
                  (if (satisfies? ITimestamp val)
                    [key (to-timestamp val)]
                    [key val])) data)))

(defn- normalize-nil-claims
  "Given a raw headers, try normalize it removing any
key with null values and convert Dates to timestamps."
  [data]
  (into {} (remove (comp nil? second) data)))

(defn- make-headers
  "Encode jws header"
  [alg extra-headers]
  (-> (or extra-headers {})
      (merge {:alg (.toUpperCase (name alg)) :typ "JWS"})
      (json/generate-string)
      (codecs/str->bytes)
      (codecs/bytes->safebase64)))

(defn- make-claims
  "Encode jws claims."
  [input exp nbf iat]
  (-> (normalize-nil-claims {:exp exp :nbf nbf :iat iat})
      (normalize-date-claims)
      (merge input)
      (json/generate-string)
      (codecs/str->bytes)
      (codecs/bytes->safebase64)))

(defn- parse-header
  "Parse jws header."
  [^String headerdata]
  (-> headerdata
      (codecs/safebase64->bytes)
      (codecs/bytes->str)
      (json/parse-string true)))

(defn- parse-claims
  "Parse jws claims"
  [^String claimsdata]
  (-> claimsdata
      (codecs/safebase64->bytes)
      (codecs/bytes->str)
      (json/parse-string true)))

(defn- parse-algorithm
  "Parse algorithm name and return a
internal keyword representation of it."
  [header]
  (let [algname (:alg header)]
    (keyword (.toLowerCase algname))))

(defn- get-verifier-for-algorithm
  "Get verifier function for algorithm name."
  [^Keyword alg]
  (when (contains? gsign/*signers-map* alg)
    (get-in gsign/*signers-map* [alg :verifier])))

(defn- get-signer-for-algorithm
  "Get signer function for algorithm name."
  [^Keyword alg]
  (when (contains? gsign/*signers-map* alg)
    (get-in gsign/*signers-map* [alg :signer])))

(defn- safe-encode
  "Properly encode string into
safe url base64 encoding."
  [^String input]
  (-> input
      (codecs/str->bytes)
      (codecs/bytes->safebase64)))

(defn- make-signature
  "Make a jws signature."
  [pkey alg header claims]
  (let [candidate (str/join "." [header claims])
        signer    (get-signer-for-algorithm alg)]
    (-> (signer candidate pkey)
        (codecs/bytes->safebase64))))

(defn sign
  "Sign arbitrary length string/byte array using json web signature."
  [claims pkey & [{:keys [alg exp nbf iat headers] :or {alg :hs256 headers {}}}]]
  {:pre [(map? claims)]}
  (let [headers-data (make-headers alg headers)
        claims-data  (make-claims claims exp nbf iat)
        signature    (make-signature pkey alg headers-data claims-data)]
    (str/join "." [headers-data claims-data signature])))

(defn unsign
  "Unsings jws and return clear caims as clojure map."
  [input pkey & [{:keys [maxage] :as opts}]]
  {:pre [(string? input)]}
  (let [[header claims signature] (str/split input #"\." 3)]
    (maybe-let [candidate (str/join "." [header claims])
                header    (parse-header header)
                claims    (parse-claims claims)
                algorithm (parse-algorithm header)
                signature (codecs/safebase64->bytes signature)
                verifier  (get-verifier-for-algorithm algorithm)
                now       (-> (jodat/now) (to-timestamp))]
      (when-let [isok? (verifier candidate signature pkey)]
        (maybe-let [_ (if (:exp claims)
                        (or (< now (:exp claims)) nil)
                        true)
                    _ (if (:nbf claims)
                        (or (< now (:nbf claims)) nil)
                        true)
                    _ (if (and (:iat claims) maxage)
                        (or (< (- now (:iat claims)) maxage) nil)
                        true)]
          claims)))))
