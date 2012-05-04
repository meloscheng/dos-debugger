/* x86_mnemonic.inc - mnemonic codes for x86 instructions */

/*
 * The mnemonics are wrapped in an I() macro to be easily manipulated by an
 * outer file that includes it. For compatibility, the order of the items must
 * not change; new items must be appended to the end of the list.
 */

/* Basic instructions */
I(HLT)
I(NOP)

/* Bitwise logical operations */
I(AND)
I(OR)
I(XOR)
I(NOT)

/* Bitwise shift */
I(SHL)
I(SHR)
I(SAL)
I(SAR)

/* Bitwise rotation */
I(ROL)
I(ROR)
I(RCL)
I(RCR)

/* Unary integer arithmetic */
I(INC)
I(DEC)
I(NEG)

/* Binary integer arithmetic */
I(ADD)
I(SUB)
I(ADC)
I(SBB)
I(MUL)
I(IMUL)
I(DIV)
I(IDIV)

/* Decimal integer adjustment */
I(DAA)
I(DAS)
I(AAA)
I(AAS)
I(AAM)
I(AAD)

/* Comparison and basic control flow */
I(CMP)
I(TEST)
I(JMP)
I(LOOP)
I(LOOPZ)
I(LOOPNZ)

/* Conditional jump */
I(JO)
I(JNO)
I(JB)
I(JNB)
I(JE)
I(JNE)
I(JBE)
I(JNBE)
I(JS)
I(JNS)
I(JP)
I(JNP)
I(JL)
I(JNL)
I(JLE)
I(JNLE)

/* Manipulating FLAGS */
I(CMC)
I(CLC)
I(STC)
I(CLD)
I(STD)
I(LAHF)
I(SAHF)
I(PUSHF)
I(POPF)

/* Calls and interrupts */
I(CALL)
I(RET)
I(INT)
I(INTO)
I(IRET)

/* Data movement */
I(MOV)
I(XCHG)
I(PUSH)
I(POP)

/* Address calculation */
I(LDS)
I(LES)
I(LEA)
I(XLATB)

/* Data extension */
I(CWD)
I(CDQ)
I(CBW)
I(CWDE)

/* IO */
I(IN)
I(INS)
I(OUT)
I(OUTS)

/* Misc */
I(PUSHA)
I(POPA)
I(BOUND)
I(ARPL)
