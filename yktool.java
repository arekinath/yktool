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
	List<Yubikey> keys;

	private
	yktool()
	{
		keys = new ArrayList<Yubikey>();
	}

	public static void
	main(String[] argv)
	{
		yktool yk = new yktool();

		if (argv.length == 0) {
			usage();
		}
		String op = argv[0];
		List<String> args = new ArrayList<String>();
		for (int i = 1; i < argv.length; ++i) {
			if (argv[i].equals("--help") || argv[i].equals("-h")) {
				usage();
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

		} else if (op.equals("get-otp") && args.size() == 1) {
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
		System.err.format("  list                   Lists yubikeys\n");
		System.err.format("  hmac <slot #>          Computes an HMAC over input data on stdin\n");
		System.err.format("  get-otp <slot #>       Gets a one-time password\n");
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
		byte[] buf = new byte[65];
		int len = 0;
		try {
			while (len < 65) {
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
			if (len > 64) {
				System.err.format("error: hmac input is " +
				    "max of 64 bytes\n");
				System.exit(1);
			}
			byte[] inp = new byte[len];
			System.arraycopy(buf, 0, inp, 0, len);
			byte[] out = keys.get(0).getHMAC(slotNum, inp);
			System.out.write(out, 0, out.length);

		} catch (Exception e) {
			System.err.format("error: %s\n", e.getMessage());
			System.exit(1);
		}
	}
}
