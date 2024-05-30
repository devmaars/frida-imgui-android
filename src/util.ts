export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export const log = (...args: any[]) => {
  const date = new Date();
  const time = [date.getHours(), date.getMinutes(), date.getSeconds()]
    .map((x) => x.toString().padStart(2, '0'))
    .join(':');

  console.log(`[${time}]`, ...args);
};
