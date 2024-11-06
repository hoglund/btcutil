import { randomNormal } from 'd3-random'

const DEVIATION = 0.03;

const getRandomAmount = (mean) => {
	const normalizedDeviation = mean * DEVIATION;
	const randomNumber = randomNormal(mean, normalizedDeviation)();
	const roundedNumber = randomNumber.toFixed(8);
	return roundedNumber;
}

export { getRandomAmount }
