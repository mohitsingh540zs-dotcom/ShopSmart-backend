import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Users",
      required: true,
      index: true
    },

    refreshTokenHash: {
      type: String,
      required: true
    },

    expiresAt: {
      type: Date,
      required: true,
      index: { expires: 0 } // MongoDB TTL (auto delete)
    },

    isValid: {
      type: Boolean,
      default: true
    },

    userAgent: {
      type: String
    },

    ipAddress: {
      type: String
    }
  },
  {
    collection: "Sessions",
    timestamps: true,
    versionKey: false
  }
);

export const Session = mongoose.model("Session", sessionSchema);
