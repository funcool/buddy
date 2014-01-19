(ns buddy.auth.backends.session
  (:require [buddy.auth.protocols :as proto]
            [buddy.crypto.core :refer [base64->str]]
            [buddy.util :refer [m-maybe]]
            [clojure.string :refer [split]]
            [ring.util.response :refer [response? header status]]))

(defrecord SessionAuthBackend [not-authorized-handler]
  proto/IAuthentication
  (parse [_ request]
    (:identity (:session request)))
  (authenticate [_ request data]
    (assoc request :identity data))

  proto/IAuthorization
  (handle-unauthorized [_ request metadata]
    (let [rsp (when not-authorized-handler
                (not-authorized-handler request metadata))
          rsp (if (response? rsp) rsp
                (if (nil? rsp) {:body ""} {:body rsp}))]
      (-> rsp
          (status 401)))))

(defn session-backend
  "Given some options, create a new instance
  of HttpBasicBackend and return it."
  [& {:keys [authorization-handler]}]
  (->SessionAuthBackend authorization-handler))
