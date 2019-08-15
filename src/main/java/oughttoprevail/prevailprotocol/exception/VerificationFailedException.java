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
package oughttoprevail.prevailprotocol.exception;

import oughttoprevail.prevailprotocol.messenger.Messenger;

/**
 * Thrown when {@link oughttoprevail.prevailprotocol.x3dh.X3DHKeyExchange} fails to verify "Bob" or when {@link Messenger} fails
 * to verify a message.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Alice_and_Bob">Who is bob</a>
 */
public class VerificationFailedException extends Exception
{
	/**
	 * Constructs a new {@link VerificationFailedException} with the specified detail message.
	 *
	 * @param message the detail message
	 */
	public VerificationFailedException(String message)
	{
		super(message);
	}
	
	public VerificationFailedException(String message, Throwable cause)
	{
		super(message, cause);
	}
}