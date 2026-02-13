// utils/otp.js
export function generateOTP(length = 6) {
  return Math.floor(
    Math.pow(10, length - 1) +
    Math.random() * Math.pow(10, length - 1)
  );
}

export function getOtpExpiry(minutes = 5) {
  return Date.now() + minutes * 60 * 1000;
}
