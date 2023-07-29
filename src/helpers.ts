export const isJsonString = (value: string): boolean => {
  try {
    JSON.parse(value);
  } catch (e) {
    return false;
  }
  return true;
};
