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

(ns buddy.auth.backends.token
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth :refer [authenticated?]]
            [buddy.sign.generic :refer [loads]]
            [buddy.util :refer [m-maybe]]
            [clojure.string :refer [split]]
            [ring.util.response :refer [response response? header status]]))

(defn parse-authorization-header
  "Given a request, try extract and parse
  authorization header."
  [request]
  (m-maybe [headers-map (:headers request)
            auth-header (get headers-map "authorization")
            pattern     (re-pattern "^Token (.+)$")
            matches     (re-find pattern auth-header)]
    (get matches 1)))

(defrecord SignedTokenBackend [pkey unauthorized-handler max-age]
  proto/Authentication
  (parse [_ request]
    (parse-authorization-header request))
  (authenticate [_ request data]
    (assoc request :identity (loads data pkey {:max-age max-age})))

  proto/Authorization
  (handle-unauthorized [_ request metadata]
    (if unauthorized-handler
      (unauthorized-handler request metadata)
      (if (authenticated? request)
        (-> (response "Permission denied")
            (status 403))
        (-> (response "Unauthorized")
            (status 401))))))

(defrecord TokenBackend [authenticate-handler unauthorized-handler]
  proto/Authentication
  (parse [_ request]
    (parse-authorization-header request))
  (authenticate [_ request token]
    (let [rsq (when authenticate-handler (authenticate-handler request token))]
      (if (response? rsq) rsq
        (assoc request :identity rsq))))

  proto/Authorization
  (handle-unauthorized [_ request metadata]
    (if unauthorized-handler
      (unauthorized-handler request metadata)
      (if (authenticated? request)
        (-> (response "Permission denied")
            (status 403))
        (-> (response "Unauthorized")
            (status 401))))))

(defn signed-token-backend
  [pkey & {:keys [unauthorized-handler max-age]}]
  (->SignedTokenBackend pkey unauthorized-handler max-age))

(defn token-backend
  [authenticate-handler & {:keys [unauthorized-handler]}]
  (->TokenBackend authenticate-handler unauthorized-handler))
