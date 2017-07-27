#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2017, Alex Wilson <alex@cooperi.net>
#

YUBI_BASE=	yubico-j/src/com/yubico/base
JAVAC_FLAGS=	-cp .:yubico-j/src

yktool.jar: yktool.class $(YUBI_BASE)/Configurator.class $(YUBI_BASE)/CRC13239.class Yubikey.class
	jar cfe $@ yktool yktool.class Yubikey.class -C yubico-j/src com/yubico/base/Configurator.class -C yubico-j/src com/yubico/base/CRC13239.class

yktool.class: $(YUBI_BASE)/Configurator.class Yubikey.class
$(YUBI_BASE)/Configurator.class: $(YUBI_BASE)/CRC13239.class

%.class: %.java
	javac $(JAVAC_FLAGS) $<

clean:
	rm -f *.jar *.class
