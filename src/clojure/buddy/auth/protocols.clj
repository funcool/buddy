(ns buddy.auth.protocols)

(defprotocol IAuthentication
  "Protocol that defines unfied workflow steps for
  all authentication backends."
  (parse [_ request]
    "Parse token (from cookie, session or any other
    http header) and return it.

    If this function returns a valid ring response,
    your handler are never called and response is returned
    inmediatelly.")
  (authenticate [_ request parsed-data]
    "Given a request and parsed data (from previous step)
    and try authenticate this data and return a new request
    object with ``:identity`` key attached.

    This method is only called if ``parse`` function,
    previouslly are returned not nil and not response data.

    Some backends can be extended with user defined function
    for as ex, lookup user information in a database, etc..."))

(defprotocol IAuthorization
  "Protocol that defines unfied workflow steps for
  authorization exceptions."
  (handle-unauthorized [_ request metadata]
    "This function is executed when a ``NotAuthorizedException``
    exception is intercepted by authorization wrapper.
    It should return a valid ring response."))
