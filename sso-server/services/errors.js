class AppError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
    this.name = "AppError";
  }
}

class OAuthError extends Error {
  constructor(status, code, description) {
    super(description);
    this.status = status;
    this.code = code;
    this.description = description;
    this.name = "OAuthError";
  }
}

module.exports = {
  AppError,
  OAuthError,
};
