/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Alex Wilson <alex@cooperi.net>
 */

import javax.smartcardio.*;
import com.yubico.base.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Yubikey
{
	private static final byte CLA_ISO = (byte)0x00;
	private static final byte CLA_CHAIN = (byte)0x10;

	private static final byte INS_SELECT = (byte)0xA4;
	private static final byte SEL_APP_AID = (byte)0x04;

	private static final byte INS_API_REQ = (byte)0x01;
	private static final byte INS_OTP = (byte)0x02;
	private static final byte INS_STATUS = (byte)0x03;
	private static final byte INS_NDEF = (byte)0x04;

	private static final byte CMD_SET_CONF_1 = (byte)0x01;
	private static final byte CMD_SET_CONF_2 = (byte)0x03;
	private static final byte CMD_UPDATE_CONF_1 = (byte)0x04;
	private static final byte CMD_UPDATE_CONF_2 = (byte)0x05;
	private static final byte CMD_SWAP = (byte)0x06;
	private static final byte CMD_GET_SERIAL = (byte)0x10;
	private static final byte CMD_DEV_CONF = (byte)0x11;
	private static final byte CMD_SET_SCAN_MAP = (byte)0x12;
	private static final byte CMD_GET_YK4_CAPS = (byte)0x13;

	private static final byte CMD_OTP_1 = (byte)0x20;
	private static final byte CMD_OTP_2 = (byte)0x28;

	private static final byte CMD_HMAC_1 = (byte)0x30;
	private static final byte CMD_HMAC_2 = (byte)0x38;

	private static final byte PGM_SEQ_INVALID = (byte)0x00;

	private static final short CONFIG1_VALID = (short)0x01;
	private static final short CONFIG1_TOUCH = (short)0x04;
	private static final short CONFIG2_VALID = (short)0x02;
	private static final short CONFIG2_TOUCH = (short)0x08;

	private static final int SW_OK = 0x9000;
	private static final int SW_CONDITIONS_NOT_SATISFIED = 0x6985;

	private static final byte[] AID_YUBIOTP = {
	    (byte)0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01
	};

	private final Card card;
	private final CardChannel chan;

	private byte[] version;
	private byte pgmSeq;
	private short touchLevel;

	private byte[] accessCode;

	private
	Yubikey(Card c, CardChannel ch)
	{
		this.card = c;
		this.chan = ch;
	}

	private void
	select() throws Exception
	{

		final CommandAPDU cmd = new CommandAPDU(
		    CLA_ISO, INS_SELECT, SEL_APP_AID, 0, AID_YUBIOTP);
		final ResponseAPDU resp = chan.transmit(cmd);
		if (resp.getSW() == SW_OK) {
			final byte[] rd = resp.getData();

			version = new byte[3];
			version[0] = rd[0];
			version[1] = rd[1];
			version[2] = rd[2];

			pgmSeq = rd[3];
		} else {
			throw (new Exception(
			    "Yubikey OTP application not supported"));
		}
	}

	private void
	updateStatus() throws Exception
	{
		select();
		final CommandAPDU cmd = new CommandAPDU(
		    CLA_ISO, INS_STATUS, 0, 0);
		final ResponseAPDU resp = chan.transmit(cmd);
		if (resp.getSW() == SW_OK) {
			final byte[] rd = resp.getData();

			version = new byte[3];
			version[0] = rd[0];
			version[1] = rd[1];
			version[2] = rd[2];

			pgmSeq = rd[3];

			touchLevel = (short)(rd[4] | (rd[5] << 8));
		} else {
			throw (new Exception(
			    "Yubikey OTP application not supported"));
		}
	}

	public long
	getSerial() throws Exception
	{
		select();

		final CommandAPDU cmd = new CommandAPDU(
		    CLA_ISO, INS_API_REQ, CMD_GET_SERIAL, 0);
		final ResponseAPDU resp = chan.transmit(cmd);
		if (resp.getSW() == SW_OK) {
			final byte[] rd = resp.getData();
			final ByteBuffer buf = ByteBuffer.allocate(4);
			buf.order(ByteOrder.BIG_ENDIAN);
			buf.put(rd);
			buf.flip();
			return (buf.getInt());
		} else {
			throw (new Exception(
			    "Yubikey serial number could not be read"));
		}
	}

	public String
	getOTP(int slot) throws Exception
	{
		select();

		final byte slotNum;
		if (slot == 1)
			slotNum = 0;
		else if (slot == 2)
			slotNum = 1;
		else
			throw (new Exception("Invalid Yubikey slot"));

		final CommandAPDU cmd = new CommandAPDU(
		    CLA_ISO, INS_OTP, slotNum, 0);
		final ResponseAPDU resp = chan.transmit(cmd);
		if (resp.getSW() == SW_OK) {
			final byte[] rd = resp.getData();
			if (rd.length < 1) {
				throw (new Exception(
				    "Yubikey slot is not configured for OTP"));
			}
			return (new String(rd));

		} else if (resp.getSW() == SW_CONDITIONS_NOT_SATISFIED) {
			throw (new Exception(
			    "Yubikey does not allow OTP to be extracted in " +
			    "this mode (e.g. connected over USB)"));
		} else {
			throw (new Exception(
			    "Yubikey failed to return an OTP"));
		}
	}

	public byte[]
	getHMAC(int slot, byte[] input) throws Exception
	{
		select();

		final byte cmdN;
		if (slot == 1)
			cmdN = CMD_HMAC_1;
		else if (slot == 2)
			cmdN = CMD_HMAC_2;
		else
			throw (new Exception("Invalid Yubikey slot"));

		final CommandAPDU cmd = new CommandAPDU(
		    CLA_ISO, INS_API_REQ, cmdN, 0, input);
		final ResponseAPDU resp = chan.transmit(cmd);
		if (resp.getSW() == SW_OK) {
			final byte[] rd = resp.getData();
			if (rd.length < 1) {
				throw (new Exception(
				    "Yubikey slot is not configured for HMAC"));
			}
			return (rd);

		} else if (resp.getSW() == SW_CONDITIONS_NOT_SATISFIED) {
			throw (new Exception(
			    "Yubikey does not allow HMAC to be extracted in " +
			    "this mode (e.g. button press required)"));
		} else {
			throw (new Exception(
			    "Yubikey failed to return an HMAC"));
		}
	}

	public static Configurator
	configForHMAC(byte[] key)
	{
		final Configurator cfg = new Configurator();
		cfg.setKey(Configurator.HMAC_SHA1_MODE, key);

		cfg.setCfgFlags((byte)(Configurator.CFGFLAG_CHAL_HMAC));
		cfg.setTktFlags(Configurator.TKTFLAG_CHAL_RESP);
		cfg.setExtFlags((byte)(
		    Configurator.EXTFLAG_SERIAL_API_VISIBLE |
		    Configurator.EXTFLAG_SERIAL_USB_VISIBLE |
		    Configurator.EXTFLAG_ALLOW_UPDATE));
		return (cfg);
	}

	public static Configurator
	configForOTP(byte[] publicId, byte[] privateId, byte[] secretKey)
	{
		final Configurator cfg = new Configurator();
		cfg.setFixed(publicId);
		cfg.setUid(privateId);
		cfg.setKey(Configurator.AES_MODE, secretKey);

		cfg.setExtFlags((byte)(
		    Configurator.EXTFLAG_SERIAL_API_VISIBLE |
		    Configurator.EXTFLAG_SERIAL_USB_VISIBLE |
		    Configurator.EXTFLAG_ALLOW_UPDATE));
		return (cfg);
	}

	public void
	program(int slot, Configurator cfg) throws Exception
	{
		select();

		final byte[] confBuf = cfg.getConfigStructure();

		final byte cmdN;
		if (slot == 1)
			cmdN = CMD_SET_CONF_1;
		else if (slot == 2)
			cmdN = CMD_SET_CONF_2;
		else
			throw (new Exception("Invalid Yubikey slot"));

		final CommandAPDU cmd = new CommandAPDU(
		    CLA_ISO, INS_API_REQ, cmdN, 0, confBuf);
		final ResponseAPDU resp = chan.transmit(cmd);
		if (resp.getSW() == SW_OK) {
			return;

		} else {
			throw (new Exception(
			    "Yubikey failed to write configuration"));
		}
	}

	public String
	getVersion()
	{
		StringBuilder sb = new StringBuilder();
		sb.append(version[0]);
		sb.append('.');
		sb.append(version[1]);
		sb.append('.');
		sb.append(version[2]);
		return (sb.toString());
	}

	public String
	toString()
	{
		StringBuilder sb = new StringBuilder();
		sb.append("Yubikey");
		if (version[0] == 3)
			sb.append(" NEO");
		else if (version[0] == 4)
			sb.append(" 4");
		try {
			long serial = getSerial();
			sb.append(" #");
			sb.append(serial);
		} catch (Exception e) {
			sb.append(" (Unknown serial #)");
		}
		sb.append(" v");
		sb.append(getVersion());

		if ((touchLevel & CONFIG1_VALID) != 0) {
			sb.append(" +slot1");
		}
		if ((touchLevel & CONFIG2_VALID) != 0) {
			sb.append(" +slot2");
		}
		return (sb.toString());
	}

	public static Yubikey
	tryCreate(Card c)
	{
		CardChannel ch = c.getBasicChannel();
		Yubikey yk = new Yubikey(c, ch);
		try {
			yk.updateStatus();
		} catch (Exception e) {
			return (null);
		}
		return (yk);
	}
}
