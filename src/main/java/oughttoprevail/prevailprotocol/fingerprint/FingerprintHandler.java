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
package oughttoprevail.prevailprotocol.fingerprint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import oughttoprevail.prevailprotocol.User;
import oughttoprevail.prevailprotocol.session.Session;
import oughttoprevail.prevailprotocol.session.SessionsManager;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.uid.UID;
import oughttoprevail.prevailprotocol.util.Consumer;

/**
 * A fingerprint (also known as safety number) handler.
 * This {@link FingerprintHandler} purpose is to notify on finger print changes, provide finger prints, format them and finally, compare them
 */
public class FingerprintHandler
{
	/**
	 * User who has created this {@link FingerprintHandler}
	 */
	private final User user;
	/**
	 * Digest for fingerprints calculations
	 */
	private final MessageDigest digest;
	/**
	 * List of fingerprint change event listeners
	 */
	private final List<Consumer<UID>> onFingerprintChange;
	
	/**
	 * Constructs a new {@link FingerprintHandler}.
	 *
	 * @param user who is creating this
	 */
	public FingerprintHandler(User user, Settings settings) throws NoSuchAlgorithmException
	{
		this.user = user;
		this.digest = MessageDigest.getInstance(settings.getFingerprintDigestAlgorithm());
		this.onFingerprintChange = new ArrayList<>();
	}
	
	/**
	 * Adds the specified onFingerprintChange to a list of event listeners waiting for finger print changes.
	 * When a fingerprint has changed the specified consumer will be invoked with the user identifier (as the argument) of the one who's fingerprint
	 * changed.
	 * Fingerprint changes occur when a new identity key is registered which happens when a new session is registered.
	 *
	 * @param onFingerprintChange to listen for finger print change events with
	 */
	public void onFingerprintChange(Consumer<UID> onFingerprintChange)
	{
		this.onFingerprintChange.add(onFingerprintChange);
	}
	
	/**
	 * @return list of finger print change listeners
	 */
	public List<Consumer<UID>> getOnFingerprintChange()
	{
		return onFingerprintChange;
	}
	
	/**
	 * @return the owner user fingerprint
	 */
	public byte[] getMyFingerprint()
	{
		return getFingerprint(user.getUserDeviceUID().getUserId(), true);
	}
	
	/**
	 * @param userId of the user who's fingerprint is to be returned
	 * @return {@code null} if there aren't any sessions with the specified userId, thus a fingerprint cannot be calculated or
	 * the fingerprint which is a digest of all the identity public keys
	 */
	public byte[] getFingerprint(UID userId)
	{
		return getFingerprint(userId, false);
	}
	
	private byte[] getFingerprint(UID userId, boolean myFingerprint)
	{
		if(myFingerprint)
		{
			digest.update(user.getIdentityPublicKey());
		}
		SessionsManager hisSessionsManager = user.getSessions().get(userId);
		if(hisSessionsManager != null)
		{
			for(Session session : hisSessionsManager.sessions())
			{
				digest.update(session.getRecipientIdentityKey());
			}
		} else if(!myFingerprint)
		{
			return null;
		}
		return digest.digest();
	}
	
	/**
	 * @param recipientUserId the user identifier of the recipient who's fingerprints is being compared
	 * @param recipientFingerprint the recipient's fingerprint
	 * @param recipientMyFingerprint the fingerprint the recipient thinks is my fingerprint
	 * @return whether the specified fingerprints match with the fingerprints registered on this handler
	 * <b>NOTE: if {@code false} is returned then it may mean there is a MITM (Man-in-the-middle) attack</b>
	 */
	public boolean compareFingerprints(UID recipientUserId, byte[] recipientFingerprint, byte[] recipientMyFingerprint)
	{
		return MessageDigest.isEqual(getFingerprint(recipientUserId), recipientFingerprint) && MessageDigest.isEqual(getMyFingerprint(),
				recipientMyFingerprint);
	}
	
	/**
	 * @param fingerprint to format
	 * @return the specified fingerprint formatted as a 30 digit {@link String}.
	 */
	public String format(byte[] fingerprint)
	{
		BigInteger fingerprintNumber = new BigInteger(fingerprint);
		String formattedFingerprint = fingerprintNumber.toString();
		//if it starts with a '-' then we should remove it
		int begin = formattedFingerprint.charAt(0) == '-' ? 1 : 0;
		//substring from the beginning to 30
		formattedFingerprint = formattedFingerprint.substring(begin, 30 + begin);
		return formattedFingerprint;
	}
	
	/**
	 * @param fingerprint any fingerprint
	 * @param fingerprint1 any fingerprint
	 * @return display {@link String} for the specified fingerprints where no matter the order the specified fingerprints are specified they will
	 * always return the same order in display
	 */
	public String display(String fingerprint, String fingerprint1)
	{
		return fingerprint.compareTo(fingerprint1) > 0 ? fingerprint + fingerprint1 : fingerprint1 + fingerprint;
	}
}