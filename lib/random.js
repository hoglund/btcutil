import { randomNormal } from 'd3-random'
import crypto from 'crypto';

const DEVIATION = 0.03;

const getRandomAmount = (mean) => {
	const normalizedDeviation = mean * DEVIATION;
	const randomNumber = randomNormal(mean, normalizedDeviation)();
	const roundedNumber = randomNumber.toFixed(8);
	return roundedNumber;
}

const getRandomNumber = () => {
	// Generate 128 bits (16 bytes) of random data
	const randomBytes = crypto.randomBytes(16);

	// Convert the random bytes to a hexadecimal string
	return randomBytes.toString('hex');
}

export { getRandomAmount, getRandomNumber }
