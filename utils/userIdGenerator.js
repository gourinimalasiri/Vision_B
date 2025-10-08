import Counter from '../models/Counter.js';

export const generateUserIdentifier = async (role) => {
  let prefix = '';
  let counterName = '';

  switch (role) {
    case 'patient':
      prefix = 'UPIN';
      counterName = 'patient';
      break;
    case 'clinical_staff':
      prefix = 'STAFF';
      counterName = 'clinical_staff';
      break;
    case 'admin':
      prefix = 'ADMIN';
      counterName = 'admin';
      break;
    default:
      throw new Error(`Unknown role: ${role}`);
  }

  return await Counter.getNextFormattedSequence(counterName, prefix, 6);
};
