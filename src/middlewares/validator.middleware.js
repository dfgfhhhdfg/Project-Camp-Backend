import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-errors.js";

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }
  const extractedErrors = [];
  errors.array().map((err) =>
    extractedErrors.push({
      [err.path]: err.msg,
    }),
  );
  throw new ApiError(404, "Recieved data is invalid", extractedErrors);

  // By the help of the express-validator package we are checking the error in the request if error is empty we are passing to next if errors are present we are pushing the errors in the extractedErrors with path and msg and we throwing the ApiError. "This is middleware it acts in between the client and server"
};

export { validate };
