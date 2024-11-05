power-mgt/psr
------------------

Some systems allow modification of how power consumption throttling
is balanced between entities in a system. A typical one may be how the power
management complex should balance throttling CPU versus the GPU. An OPAL
call can be used to set these ratios, which are described in the device
tree.

In the future, there may be more available settings than just CPU
versus GPU.

Each child node in the "psr" node represents a configurable psr
sensor.

For example : ::
        cpu-to-gpu@1

The compatible property is set to "ibm,opal-power-shift-ratio".

Each child node has below properties:

`handle`
  Handle to indicate the type of psr

`label`
  Name of the psr sensor

The format of the handle is internal, and ``not`` ABI, although
currently it uses the following encoding ::

	| Class |Reserved|  RID	| Type |
	|-------|--------|------|------|

.. code-block:: dts

   power-mgt {
     psr {
        compatible = "ibm,opal-power-shift-ratio";

        cpu-to-gpu@0 {
                name = "cpu-to-gpu";
                handle = <0x00000000>;
                label = "cpu_to_gpu_0";
        };

        cpu-to-gpu@1 {
                name = "cpu-to-gpu";
                handle = <0x00000100>;
                label = "cpu_to_gpu_1";
        };
     };
    };
