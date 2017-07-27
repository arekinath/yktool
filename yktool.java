/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Alex Wilson <alex@cooperi.net>
 */

import javax.smartcardio.*;
import java.util.List;
import java.util.ArrayList;

public class yktool
{
	public List<Yubikey> keys;
	public boolean hexInputs = false;
	public boolean hexOutputs = false;

	private
	yktool()
	{
		keys = new ArrayList<Yubikey>();
	}

	public static void
	main(String[] argv)
	{
		yktool yk = new yktool();
		byte[] curAccessCode = null;
		byte[] newAccessCode = null;

		if (argv.length == 0) {
			usage();
		}
		String op = argv[0];
		List<String> args = new ArrayList<String>();
		for (int i = 1; i < argv.length; ++i) {
			if (argv[i].equals("--help") || argv[i].equals("-h")) {
				usage();

			} else if (argv[i].equals("--hex-in") ||
			    argv[i].equals("-X")) {
				yk.hexInputs = true;

			} else if (argv[i].equals("--hex-out") ||
			    argv[i].equals("-x")) {
				yk.hexOutputs = true;

			} else if (argv[i].equals("--acc-code") ||
			    argv[i].equals("-c")) {
				curAccessCode = parseHex(
				    argv[++i].getBytes(), -1);

			} else if (argv[i].equals("--set-acc-code") ||
			    argv[i].equals("-C")) {
				newAccessCode = parseHex(
				    argv[++i].getBytes(), -1);

			} else if (argv[i].charAt(0) == '-') {
				usage();
			} else {
				args.add(argv[i]);
			}
		}

		try {
			yk.findYubikeys();
		} catch (CardException e) {
			System.err.format("error: %s\n", e.getMessage());
			System.exit(1);
		}

		if (op.equals("list")) {
			yk.list();

		} else if (op.equals("otp") && args.size() == 1) {
			yk.getOtp(Integer.parseInt(args.get(0)));

		} else if (op.equals("hmac") && args.size() == 1) {
			yk.getHmac(Integer.parseInt(args.get(0)));

		} else {
			usage();
		}
	}

	private static void
	usage()
	{
		System.err.format("Usage: yktool <operation> [options]\n\n");
		System.err.format("Available operations:\n");
		System.err.format("  list                           Lists yubikeys\n");
		System.err.format("  hmac <slot #>                  Computes an HMAC over input data on stdin\n");
		System.err.format("  otp <slot #>                   Gets a one-time password\n");
		System.err.format("  program hmac [opts] <slot #>   Configure a slot for HMAC. Key in stdin.\n");
		System.err.format("  program otp [opts] <slot #> <pubid> <privid>\n");
		System.err.format("                                 Configure a slot for OTP. Args in hex.\n");
		System.err.format("Options:\n");
		System.err.format("  --hex|-x                       stdin inputs are hex\n");
		System.err.format("Options for programming:\n");
		System.err.format("  --acc-code|-c <hex>            Access code for protected slot\n");
		System.err.format("  --set-acc-code|-C <hex>        Change protection code\n");
		System.exit(1);
	}

	private void
	findYubikeys() throws CardException
	{
		TerminalFactory factory = TerminalFactory.getDefault();
		List<CardTerminal> terms = factory.terminals().list();

		for (CardTerminal term : terms) {
			Card card;
			try {
				card = term.connect("T=1");
			} catch (CardException e) {
				continue;
			}
			Yubikey yk = Yubikey.tryCreate(card);
			if (yk != null) {
				keys.add(yk);
			}
		}
	}

	private void
	list()
	{
		System.err.println("Yubikeys available:");
		for (Yubikey yk : keys) {
			System.out.format("  - %s\n", yk.toString());
		}
	}

	private void
	getOtp(int slotNum)
	{
		try {
			String otp = keys.get(0).getOTP(slotNum);
			System.out.println(otp);
		} catch (Exception e) {
			System.err.format("error: %s\n", e.getMessage());
			System.exit(1);
		}
	}

	private void
	getHmac(int slotNum)
	{
		byte[] buf = new byte[1024];
		int len = 0;
		try {
			while (len < 1024) {
				int b = System.in.read();
				if (b == -1)
					break;
				buf[len++] = (byte)b;
			}
			if (len < 1) {
				System.err.format("error: need at least 1 " +
				    "byte of input\n");
				System.exit(1);
			}
			if (hexInputs) {
				buf = parseHex(buf, len);
				len = buf.length;
			}
			if (len > 64) {
				System.err.format("error: hmac input is " +
				    "max of 64 bytes\n");
				System.exit(1);
			}
			byte[] inp = new byte[len];
			System.arraycopy(buf, 0, inp, 0, len);
			byte[] out = keys.get(0).getHMAC(slotNum, inp);
			if (hexOutputs) {
				System.out.println(toHex(out));
			} else {
				System.out.write(out, 0, out.length);
			}

		} catch (Exception e) {
			System.err.format("error: %s\n", e.getMessage());
			System.exit(1);
		}
	}

	private static String
	toHex(byte[] inp)
	{
		StringBuilder sb = new StringBuilder();
		int idx = 0;
		int shift = 4;
		while (idx < inp.length) {
			final char c;
			int mask = (shift == 4 ? 0xf0 : 0x0f);
			int val = (inp[idx] & mask) >> shift;
			if (val >= 0xA) {
				c = (char)('A' + (char)(val - 0xA));
			} else {
				c = (char)('0' + (char)val);
			}
			sb.append(c);
			if (shift == 4) {
				shift = 0;
			} else if (shift == 0) {
				++idx;
				shift = 4;
				if (idx < inp.length)
					sb.append(':');
			}
		}
		return (sb.toString());
	}

	private static byte[]
	parseHex(byte[] inp, int len)
	{
		if (len == -1)
			len = inp.length;
		byte[] data = new byte[len / 2];
		int idx = 0;
		int shift = 4;
		for (int i = 0; i < len; ++i) {
			final char c = (char)(inp[i]);
			boolean skip = false;
			if (c >= '0' && c <= '9') {
				data[idx] |= (c - '0') << shift;
			} else if (c >= 'a' && c <= 'f') {
				data[idx] |= (c - 'a' + 0xa) << shift;
			} else if (c >= 'A' && c <= 'F') {
				data[idx] |= (c - 'A' + 0xA) << shift;
			} else if (c == ':' || c == ' ' || c == '\t' ||
			    c == '\n' || c == '\r') {
				skip = true;
			} else {
				System.err.format(
				    "error: invalid hex digit: '%c'\n", c);
				System.exit(1);
				return (null);
			}
			if (!skip) {
				if (shift == 4) {
					shift = 0;
				} else if (shift == 0) {
					++idx;
					shift = 4;
				}
			}
		}
		if (shift == 0) {
			System.err.format(
			    "error: odd number of hex digits (incomplete)\n");
			System.exit(1);
			return (null);
		}
		if (idx < data.length) {
			byte[] output = new byte[idx];
			System.arraycopy(data, 0, output, 0, idx);
			return (output);
		}
		return (data);
	}
}
