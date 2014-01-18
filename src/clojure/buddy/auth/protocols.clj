(ns buddy.auth.protocols)

(defprotocol IAuthentication
  "Base protocol for all authentication backends."
  (parse [_ request]
    "Parse token (from cookie, settings or any other
    http header) and attach it to request.")
  (authenticate [_ request parsed-data]
    "Use parsed data from previous step and lookup
    user information related to parsed token. (Ex: search
    a user in a database that corresponds to parsed token
    or attach anonymous user)"))

(defprotocol IAuthorization
  "Base protocol for all authorization backends."
  (do-unauthorized [_ request metadata]
    "Execute when a authenticated user enters on unathorized
    location and unauthorized exception is raised.")
  (do-unauthenticated [_ request metadata]
    "Execute when a unauthenticated user enters on unauthorized
    location and unauthorized exception is raised."))

