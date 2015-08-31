/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2015 B. Malinowsky

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

package tuwien.auto.calimero.device;

import org.slf4j.Logger;

import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.DetachEvent;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXIllegalStateException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.dptxlator.DPTXlator;
import tuwien.auto.calimero.dptxlator.DPTXlator2ByteFloat;
import tuwien.auto.calimero.dptxlator.DPTXlator3BitControlled;
import tuwien.auto.calimero.dptxlator.DPTXlator4ByteFloat;
import tuwien.auto.calimero.dptxlator.DPTXlator8BitUnsigned;
import tuwien.auto.calimero.dptxlator.DPTXlatorBoolean;
import tuwien.auto.calimero.dptxlator.DPTXlatorString;
import tuwien.auto.calimero.dptxlator.TranslatorTypes;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.process.ProcessCommunicationBase;
import tuwien.auto.calimero.process.ProcessListener;

/**
 * Writes process communication group responses to a KNX network.
 * <p>
 * This implementation for process communication uses in any case the DPT translators
 * {@link DPTXlatorBoolean}, {@link DPTXlator3BitControlled}, {@link DPTXlator8BitUnsigned},
 * {@link DPTXlator2ByteFloat}, {@link DPTXlator4ByteFloat}, link DPTXlatorString}. Other translator
 * types are loaded using the {@link TranslatorTypes} API.
 *
 * @author B. Malinowsky
 */
public class ProcessCommunicationResponder implements ProcessCommunicationBase
{
	private static final int GROUP_RESPONSE = 0x40;

	private final KNXNetworkLink lnk;
	private final EventListeners<ProcessListener> listeners;
	private volatile Priority priority = Priority.LOW;

	private volatile boolean detached;
	private final Logger logger;

	/**
	 * Creates a new process communicator attached to the supplied KNX network link.
	 * <p>
	 * The log service used by this process communicator is named "process " +
	 * <code>link.getName()</code>.
	 *
	 * @param link network link used for communication with a KNX network
	 * @throws KNXLinkClosedException if the network link is closed
	 */
	public ProcessCommunicationResponder(final KNXNetworkLink link) throws KNXLinkClosedException
	{
		if (!link.isOpen())
			throw new KNXLinkClosedException(
					"cannot initialize process communication using closed link " + link.getName());
		lnk = link;
		logger = LogService.getLogger("process " + link.getName());
		listeners = new EventListeners<>(logger);
	}

	@Override
	public void setPriority(final Priority p)
	{
		priority = p;
	}

	@Override
	public Priority getPriority()
	{
		return priority;
	}

	@Override
	public void addProcessListener(final ProcessListener l)
	{
		listeners.add(l);
	}

	@Override
	public void removeProcessListener(final ProcessListener l)
	{
		listeners.remove(l);
	}

	@Override
	public void write(final GroupAddress dst, final boolean value)
		throws KNXTimeoutException, KNXLinkClosedException
	{
		try {
			final DPTXlatorBoolean t = new DPTXlatorBoolean(DPTXlatorBoolean.DPT_BOOL);
			t.setValue(value);
			write(dst, priority, t);
		}
		catch (final KNXFormatException ignore) {}
	}

	@Override
	public void write(final GroupAddress dst, final int value, final String scale)
		throws KNXTimeoutException, KNXFormatException, KNXLinkClosedException
	{
		final DPTXlator8BitUnsigned t = new DPTXlator8BitUnsigned(scale);
		t.setValue(value);
		write(dst, priority, t);
	}

	@Override
	public void write(final GroupAddress dst, final boolean control, final int stepcode)
		throws KNXTimeoutException, KNXFormatException, KNXLinkClosedException
	{
		final DPTXlator3BitControlled t = new DPTXlator3BitControlled(
				DPTXlator3BitControlled.DPT_CONTROL_DIMMING);
		t.setValue(control, stepcode);
		write(dst, priority, t);
	}

	@Override
	public void write(final GroupAddress dst, final float value, final boolean use4ByteFloat)
		throws KNXTimeoutException, KNXFormatException, KNXLinkClosedException
	{
		if (use4ByteFloat) {
			final DPTXlator4ByteFloat t = new DPTXlator4ByteFloat(
					DPTXlator4ByteFloat.DPT_TEMPERATURE_DIFFERENCE);
			t.setValue(value);
			write(dst, priority, t);
		}
		else {
			final DPTXlator2ByteFloat t = new DPTXlator2ByteFloat(
					DPTXlator2ByteFloat.DPT_RAIN_AMOUNT);
			t.setValue(value);
			write(dst, priority, t);
		}
	}

	@Override
	public void write(final GroupAddress dst, final String value)
		throws KNXTimeoutException, KNXFormatException, KNXLinkClosedException
	{
		final DPTXlatorString t = new DPTXlatorString(DPTXlatorString.DPT_STRING_8859_1);
		t.setValue(value);
		write(dst, priority, t);
	}

	/**
	 * Writes the supplied application layer data to a group destination.
	 * <p>
	 * The data is interpreted as application layer service data and not further formatted;
	 * therefore, is assumed to have the correct layout for the datapoint associated with the
	 * destination group address.
	 *
	 * @param dst group destination to write to
	 * @param asdu application layer service data unit
	 * @param lengthOptimizedApdu <code>true</code> to use a length-optimized APDU,
	 *        <code>false</code> to use a standard APDU
	 * @throws KNXTimeoutException on a timeout during send
	 * @throws KNXLinkClosedException if network link to KNX network is closed
	 */
	public void write(final GroupAddress dst, final byte[] asdu, final boolean lengthOptimizedApdu)
		throws KNXTimeoutException, KNXLinkClosedException
	{
		if (detached)
			throw new KNXIllegalStateException("process communicator detached");

		final byte[] buf = lengthOptimizedApdu
				? DataUnitBuilder.createLengthOptimizedAPDU(GROUP_RESPONSE, asdu)
				: DataUnitBuilder.createAPDU(GROUP_RESPONSE, asdu);

		lnk.sendRequest(dst, priority, buf);
	}

	@Override
	public void write(final GroupAddress dst, final DPTXlator value) throws KNXException
	{
		write(dst, priority, value);
	}

	@Override
	public void write(final Datapoint dp, final String value) throws KNXException
	{
		final DPTXlator t = TranslatorTypes.createTranslator(dp.getMainNumber(), dp.getDPT());
		t.setValue(value);
		write(dp.getMainAddress(), dp.getPriority(), t);
	}

	@Override
	public KNXNetworkLink detach()
	{
		synchronized (this) {
			// wait of response time seconds
			if (detached)
				return null;
			detached = true;
		}
		//lnk.removeLinkListener(lnkListener);
		fireDetached();
		logger.info("detached from " + lnk.getName());
		LogService.removeLogger(logger);
		return lnk;
	}

	private void write(final GroupAddress dst, final Priority p, final DPTXlator t)
		throws KNXTimeoutException, KNXLinkClosedException
	{
		if (detached)
			throw new KNXIllegalStateException("process communicator detached");
		lnk.sendRequest(dst, p, createGroupAPDU(GROUP_RESPONSE, t));
	}

	private void fireDetached()
	{
		final DetachEvent e = new DetachEvent(this);
		listeners.fire(l -> l.detached(e));
	}

	// createGroupAPDU and extractGroupASDU helper would actually better fit
	// into to DataUnitBuilder, but moved here to avoid DPT dependencies

	/**
	 * Creates a group service application layer protocol data unit containing all items of a DPT
	 * translator.
	 * <p>
	 * The transport layer bits in the first byte (TL / AL control field) are set 0. The maximum
	 * length used for the ASDU is not checked.<br>
	 * For DPTs occupying &lt;= 6 bits in length the optimized (compact) group write / response
	 * format layout is used.
	 *
	 * @param service application layer group service code
	 * @param t DPT translator with items to put into ASDU
	 * @return group APDU as byte array
	 */
	private static byte[] createGroupAPDU(final int service, final DPTXlator t)
	{
		// check for group read
		if (service == 0x00)
			return new byte[2];
		// only group response and group write are allowed
		if (service != 0x40 && service != 0x80)
			throw new KNXIllegalArgumentException("not an APDU group service");
		// determine if data starts at byte offset 1 (optimized) or 2 (default)
		final int offset = t.getItems() == 1 && t.getTypeSize() == 0 ? 1 : 2;
		final byte[] buf = new byte[t.getItems() * Math.max(1, t.getTypeSize()) + offset];
		buf[0] = (byte) (service >> 8);
		buf[1] = (byte) service;
		return t.getData(buf, offset);
	}
}
