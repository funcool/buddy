(ns buddy.auth.backends.session
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth :refer [authenticated?]]
            [buddy.crypto.core :refer [base64->str]]
            [buddy.util :refer [m-maybe]]
            [clojure.string :refer [split]]
            [ring.util.response :refer [response response? header status]]))

(defrecord SessionAuthBackend [unauthorized-handler]
  proto/IAuthentication
  (parse [_ request]
    (:identity (:session request)))
  (authenticate [_ request data]
    (assoc request :identity data))

  proto/IAuthorization
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
  (->SessionAuthBackend unauthorized-handler))
