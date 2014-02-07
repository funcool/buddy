;; Copyright 2013 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.auth.backends.stateless-token
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth :refer [authenticated?]]
            [buddy.crypto.keys :refer [make-secret-key]]
            [buddy.crypto.signing :refer [loads]]
            [buddy.util :refer [m-maybe]]
            [clojure.string :refer [split]]
            [ring.util.response :refer [response response? header status]]))

(defn parse-authorization-header
  "Given a request, try extract and parse
  authorization header."
  [request]
  (m-maybe [headers-map (:headers request)
            auth-header (get headers-map "authorization")
            pattern     (re-pattern "^Bearer (.+)$")
            matches     (re-find pattern auth-header)]
    (get matches 1)))

(defrecord StatelessTokenAuthBackend [pkey unauthorized-handler maxage]
  proto/IAuthentication
  (parse [_ request]
    (parse-authorization-header request))
  (authenticate [_ request data]
    (assoc request :identity (loads data pkey {:maxage maxage})))

  proto/IAuthorization
  (handle-unauthorized [_ request metadata]
    (if unauthorized-handler
      (unauthorized-handler request metadata)
      (if (authenticated? request)
        (-> (response "Permission denied")
            (status 403))
        (-> (response "Unauthorized")
            (status 401))))))

(defn stateless-token-backend
  "Given some options, create a new instance
  of HttpBasicBackend and return it."
  [pkey & {:keys [unauthorized-handler maxage]}]
  (->StatelessTokenAuthBackend
    (make-secret-key pkey)
    unauthorized-handler
    maxage))
