(ns buddy.core
  (:require [buddy.core.keys :refer [make-secret-key]]))

(def ^:dynamic *secret-key* (make-secret-key ""))
