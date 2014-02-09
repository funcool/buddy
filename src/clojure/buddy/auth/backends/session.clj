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

(ns buddy.auth.backends.session
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth :refer [authenticated?]]
            [buddy.util :refer [m-maybe]]
            [clojure.string :refer [split]]
            [ring.util.response :refer [response response? header status]]))

(defrecord SessionBackend [unauthorized-handler]
  proto/Authentication
  (parse [_ request]
    (:identity (:session request)))
  (authenticate [_ request data]
    (assoc request :identity data))

  proto/Authorization
  (handle-unauthorized [_ request metadata]
    (if unauthorized-handler
      (unauthorized-handler request metadata)
      (if (authenticated? request)
        (-> (response "Permission denied")
            (status 403))
        (-> (response "Unauthorized")
            (status 401))))))

(defn session-backend
  "Given some options, create a new instance
  of HttpBasicBackend and return it."
  [& {:keys [unauthorized-handler]}]
  (->SessionBackend unauthorized-handler))
