import { ApiResponse } from "../utils/api-response.js";
import { asyncHandler } from "../utils/async-handler.js";
/*
const healthCheck = async (req, res, next) => {
  try {
    const user = await getUserFormDB();
    res.status(200).json(new ApiResponse(200, { message: "Sever is running" }));
  } catch (error) {
    next(err);
  }
};
*/

const healthCheck = asyncHandler(async (req, res, next) => {
  res.status(200).json(new ApiResponse(200, { message: "Sever is  running" }));
});

export { healthCheck };
