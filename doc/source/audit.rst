Audit
=====

Anchor produces audit messages using the PyCADF library and aims for CADF
compatibility. The two events being emited right now are ``audit.sign`` and
``audit.auth``, used for certificate signing and authentication events
respectively.

In the configuration, audit events can be sent either to the log stream, or
to the standard openstack message queue. This is configured using the
``audit.target`` option. See the :doc:`configuration section <configuration>`
for more details.

Capturing events in Ceilometer
------------------------------

In order to get events processed by Ceilometer, two configuration files need to
be provided - event pipeline and definitions. The default
``event_pipeline.yaml`` as described in Ceilometer documentation is compatible
with Anchor. As for ``event_definitions.yaml``, it needs to include the
``audit.auth`` and ``audit.sign`` events.

On the Ceilometer side, it needs the `notification agent`_ installed in order
to receive data from the message queue. Add incoming events will then be saved
and visible after running ``ceilometer event-list``.

.. _notification agent: http://docs.openstack.org/developer/ceilometer/architecture.html#notification-agents-listening-for-data
