/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2023 B. Malinowsky

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Linking this library statically or dynamically with other modules is
    making a combined work based on this library. Thus, the terms and
    conditions of the GNU General Public License cover the whole
    combination.

    As a special exception, the copyright holders of this library give you
    permission to link this library with independent modules to produce an
    executable, regardless of the license terms of these independent
    modules, and to copy and distribute the resulting executable under terms
    of your choice, provided that you also meet, for each linked independent
    module, the terms and conditions of the license of that module. An
    independent module is a module which is not derived from or based on
    this library. If you modify this library, you may extend this exception
    to your version of the library, but you are not obligated to do so. If
    you do not wish to do so, delete this exception statement from your
    version.
*/

package io.calimero.device;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.calimero.DeviceDescriptor;
import io.calimero.IndividualAddress;
import io.calimero.KNXAddress;
import io.calimero.KNXException;
import io.calimero.KNXTimeoutException;
import io.calimero.KnxRuntimeException;
import io.calimero.ReturnCode;
import io.calimero.cemi.CEMILData;
import io.calimero.datapoint.Datapoint;
import io.calimero.dptxlator.DPTXlator;
import io.calimero.link.AbstractLink;
import io.calimero.link.KNXLinkClosedException;
import io.calimero.link.KNXNetworkLink;
import io.calimero.link.medium.TPSettings;
import io.calimero.mgmt.Description;
import io.calimero.mgmt.Destination;
import io.calimero.mgmt.PropertyAccess.PID;
import io.calimero.mgmt.TransportLayer;
import io.calimero.mgmt.TransportLayerImpl;

class ManagementServiceTest
{
	private static final int objectIndex = 0;
	private static final int propertyId = PID.OBJECT_TYPE;

	private KnxDeviceServiceLogic mgmt;
	private BaseKnxDevice device;
	private TransportLayer tl;
	private Destination dst;

	private static final byte[] authKey = { 0x10, 0x20, 0x30, 0x40 };
	private static final byte[] highestAuthKey = { 0x50, 0x60, 0x70, (byte) 0x80 };
	private static final byte[] defaultAuthKey = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

	@BeforeEach
	void init() throws Exception
	{
		final KNXNetworkLink link = new AbstractLink<>("test link",
				new TPSettings(new IndividualAddress(0, 0x02, 0xff))) {
			@Override
			protected void onSend(final CEMILData msg, final boolean waitForCon) {}

			@Override
			protected void onSend(final KNXAddress dst, final byte[] msg, final boolean waitForCon) {}
		};

		mgmt = new KnxDeviceServiceLogic() {
			@Override
			public void updateDatapointValue(final Datapoint ofDp, final DPTXlator update)
			{
				fail("not under test");
			}

			@Override
			public DPTXlator requestDatapointValue(final Datapoint ofDp) {
				fail("not under test");
				return null;
			}
		};

		device = new BaseKnxDevice("test", DeviceDescriptor.DD0.TYPE_5705, link, null, mgmt);
		mgmt.setDevice(device);
		mgmt.authKeys[0] = highestAuthKey;
		mgmt.authKeys[3] = authKey;
		mgmt.minAccessLevel = 15;

		tl = new TransportLayerImpl(link);
		dst = tl.createDestination(new IndividualAddress(1), true);
		tl.connect(dst);
	}

	@AfterEach
	void cleanup() throws KNXLinkClosedException {
		device.setDeviceLink(null);
	}

	@Test
	void readProperty()
	{
		mgmt.authorize(dst, authKey);
		final ServiceResult<byte[]> r = mgmt.readProperty(dst, objectIndex, propertyId, 1, 1);
		assertNotNull(r);
		assertNotNull(r.result());
		assertEquals(2, r.result().length);
	}

	@Test
	void writeProperty()
	{
		mgmt.authorize(dst, authKey);
		final byte[] data = { 1 };
		final int pidPL110Param = 73;
		final ServiceResult<Void> r = mgmt.writeProperty(dst, objectIndex, pidPL110Param, 1, 1, data);
		assertNotNull(r);
		assertNotNull(r.result());

		mgmt.authorize(dst, highestAuthKey);
		final ServiceResult<byte[]> read = mgmt.readProperty(dst, objectIndex, pidPL110Param, 1, 1);
		assertNotNull(read);
		assertNotNull(read.result());
		assertArrayEquals(data, read.result());
	}

	@Test
	void tryWriteReadOnlyProperty()
	{
		mgmt.authorize(dst, authKey);
		ServiceResult<byte[]> r = mgmt.readProperty(dst, objectIndex, propertyId, 1, 1);
		byte[] data = r.result();
		final var sr = mgmt.writeProperty(null, objectIndex, propertyId, 1, 1, data);
		assertEquals(ReturnCode.AccessReadOnly, sr.returnCode());

		r = mgmt.readProperty(dst, 1, propertyId, 1, 1);
		data = r.result();
		final var sr2 = mgmt.writeProperty(dst, 1, propertyId, 1, 1, data);
		assertEquals(ReturnCode.AccessReadOnly, sr2.returnCode());
	}

	@Test
	void readPropertyDescription()
	{
		ServiceResult<Description> r = mgmt.readPropertyDescription(objectIndex, propertyId, 0);
		assertNotNull(r);
		assertNotNull(r.result());

		r = mgmt.readPropertyDescription(objectIndex, 0, 0);
		assertNotNull(r);
		assertNotNull(r.result());
	}

	@Test
	void readMemory()
	{
		final ServiceResult<byte[]> r = mgmt.readMemory(0x60, 1);
		assertNotNull(r);
		assertNotNull(r.result());
		assertEquals(1, r.result().length);
		assertEquals(0, r.result()[0]);
	}

	@Test
	void writeMemory()
	{
		final int start = 0x22;
		final byte[] data = { 1, 2, 3, 4 };

		final ServiceResult<Void> r = mgmt.writeMemory(start, data);
		assertNotNull(r);
		assertNotNull(r.result());

		final ServiceResult<byte[]> read = mgmt.readMemory(start, 4);
		assertNotNull(read);
		assertNotNull(read.result());
		assertArrayEquals(data, read.result());
	}

	@Test
	void readDescriptor()
	{
		final ServiceResult<DeviceDescriptor> r = mgmt.readDescriptor(0);
		assertNotNull(r);
		assertNotNull(r.result());
		assertThrows(KnxRuntimeException.class, () -> mgmt.readDescriptor(2));
	}

	@Test
	void authorizeInvalidKey()
	{
		assertAuthResult(mgmt.authorize(dst, new byte[] { 3, 3, 3, 3 }), 0xf);
	}

	@Test
	void authorizeFreeAccess()
	{
		assertAuthResult(mgmt.authorize(dst, defaultAuthKey), 0x1);
	}

	@Test
	void modifyAuthKey()
	{
		assertAuthResult(mgmt.authorize(dst, authKey), 3);
		assertAuthResult(mgmt.writeAuthKey(dst, 4, new byte[] { 4, 4, 4, 4 }), 4);
		assertAuthResult(mgmt.authorize(dst, new byte[] { 4, 4, 4, 4 }), 4);
	}

	@Test
	void modifyAuthKeyForCurrentAccessLevel()
	{
		assertAuthResult(mgmt.authorize(dst, authKey), 3);
		assertAuthResult(mgmt.writeAuthKey(dst, 3, new byte[] { 4, 4, 4, 4 }), 3);
		assertAuthResult(mgmt.authorize(dst, new byte[] { 4, 4, 4, 4 }), 3);
	}

	@Test
	void resetAuthKey()
	{
		mgmt.authorize(dst, authKey);
		assertAuthResult(mgmt.writeAuthKey(dst, 4, new byte[] { 4, 4, 4, 4 }), 4);
		assertAuthResult(mgmt.writeAuthKey(dst, 4, defaultAuthKey), 4);
		assertAuthResult(mgmt.authorize(dst, new byte[] { 4, 4, 4, 4 }), 0xf);
	}

	@Test
	void writeAuthKeyWithFreeLevelAuthorization()
	{
		assertAuthResult(mgmt.writeAuthKey(dst, 5, new byte[] { 5, 5, 5, 5 }), 0x5);
		assertAuthResult(mgmt.authorize(dst, new byte[] { 5, 5, 5, 5 }), 0x5);
	}

	@Test
	void writeAuthKeyWithoutAuthorization() throws KNXTimeoutException, KNXLinkClosedException {
		assertAuthResult(mgmt.writeAuthKey(dst, 0, new byte[] { 5, 5, 5, 5 }), 0xff);
		assertAuthResult(mgmt.writeAuthKey(dst, 1, new byte[] { 5, 5, 5, 5 }), 1);

		dst.destroy();
		final var noAuth = tl.createDestination(new IndividualAddress(1), true);
		tl.connect(noAuth);
		assertAuthResult(mgmt.writeAuthKey(dst, 1, new byte[] { 5, 5, 5, 5 }), 0xff);
		assertAuthResult(mgmt.authorize(dst, new byte[] { 5, 5, 5, 5 }), 1);
	}

	private void assertAuthResult(final ServiceResult<Integer> r, final int level)
	{
		assertNotNull(r);
		assertNotNull(r.result());
		assertEquals(level, r.result());
	}
}
