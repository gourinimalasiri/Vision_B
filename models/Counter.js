import mongoose from 'mongoose';

const counterSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
  },
  value: {
    type: Number,
    required: true,
    default: 0,
  },
  prefix: {
    type: String,
    default: '',
  },
  description: {
    type: String,
  },
});

// Static method to get next sequence value with formatting
counterSchema.statics.getNextSequence = async function (name, prefix = '') {
  const result = await this.findOneAndUpdate(
    { name },
    {
      $inc: { value: 1 },
      ...(prefix && { prefix }),
    },
    { new: true, upsert: true },
  );
  return prefix
    ? `${prefix}${result.value.toString().padStart(6, '0')}`
    : result.value;
};

// Static method to get formatted identifier
counterSchema.statics.getNextFormattedSequence = async function (
  name,
  prefix = '',
  padding = 6,
) {
  const result = await this.findOneAndUpdate(
    { name },
    {
      $inc: { value: 1 },
      ...(prefix && { prefix }),
    },
    { new: true, upsert: true },
  );
  return `${prefix}${result.value.toString().padStart(padding, '0')}`;
};

const Counter = mongoose.model('Counter', counterSchema);

export default Counter;
