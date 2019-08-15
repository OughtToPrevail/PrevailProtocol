/*
PrevailProtocol.
Copyright (C) 2019  https://github.com/OughtToPrevail

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package oughttoprevail.prevailprotocol.nonce;

import oughttoprevail.prevailprotocol.random.RandomBytesGenerator;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link NonceGenerator} generates nonce using a random and a counter.
 * Random achieves the unpredictability of the nonce.
 * Counter achieves the uniqueness (never repeating) of the nonce.
 * The nonce will look as the following random|counter.
 * Random will be have constant length specified in the constructor and counter will always be {@link Util#INT_BYTES} length.
 */
public abstract class NonceGenerator
{
	/**
	 * Minimum size of the random part of the nonce
	 */
	private static final int MIN_RANDOM_SIZE = 6;
	
	/**
	 * Will generate a random {@code byte[]} to make the nonce unpredictable.
	 */
	private final RandomBytesGenerator randomBytesGenerator;
	/**
	 * Size of the random {@code byte[]}.
	 */
	private final int randomSize;
	
	/**
	 * Constructs a new {@link NonceGenerator} with the specified settings, specified totalSize and specified whatToIncrease.
	 *
	 * @param settings to use
	 * @param totalSize to be the total size in bytes of the nonce
	 * @param whatToIncrease is what needs to be increased if the specified totalSize is too low
	 */
	NonceGenerator(Settings settings, int totalSize, String whatToIncrease)
	{
		this.randomBytesGenerator = settings.getRandom();
		randomSize = totalSize - Util.INT_BYTES;
		if(randomSize < MIN_RANDOM_SIZE)
		{
			throw new IllegalArgumentException("Random size must be at least " +
											   MIN_RANDOM_SIZE +
											   " (Current: " +
											   randomSize +
											   ")! To increase the randomSize, increase the " +
											   whatToIncrease +
											   " in Settings.");
		}
	}
	
	/**
	 * Generates a nonce.
	 * A nonce will be a random|counter.
	 *
	 * @return a nonce
	 */
	public byte[] generateNonce()
	{
		byte[] random = randomBytesGenerator.nextBytes(randomSize);
		return Util.combine(random, getCounterBytes());
	}
	
	/**
	 * The return value length must be equal to {@link Util#INT_BYTES}.
	 *
	 * @return a counter represented as a {@code byte[]}
	 */
	abstract byte[] getCounterBytes();
}