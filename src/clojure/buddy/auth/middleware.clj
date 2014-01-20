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

(ns buddy.auth.middleware
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth :refer [authenticated?]]
            [buddy.util :refer [m-maybe]]
            [ring.util.response :refer [response response?]])
  (:import (buddy.exceptions NotAuthorizedException)))

(defn wrap-authentication
  "Ring middleware that enables authentication
  for your ring handler."
  [handler backend]
  (fn [request]
    (let [request (assoc request :auth-backend backend)
          rsq     (proto/parse backend request)]
      (if (response? rsq) rsq
        (if (nil? rsq)
          (handler request)
          (let [rsq (proto/authenticate backend request rsq)]
            (if (response? rsq) rsq
              (handler (or rsq request)))))))))

(defn wrap-authorization
  "Ring middleware that enables authorization
  workflow for your ring handler."
  [handler & [backend]]
  (fn [request]
    (let [backend (or backend (:auth-backend request))]
      (if (nil? backend)
        (throw (IllegalAccessError. "no backend found"))
        (try
          (handler request)
          (catch NotAuthorizedException e
            (proto/handle-unauthorized backend request (.getMetadata e))))))))
