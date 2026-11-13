package org.ratscanner;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.nio.charset.StandardCharsets;
import java.util.*;

final class StringEmulator {

    record Decoded(String value, int line) {
    }

    private static final Object UNKNOWN = new Object();

    private static final class Arr {
        final int[] data;
        final boolean chars;
        int stores;

        Arr(int size, boolean chars) {
            this.data = new int[size];
            this.chars = chars;
        }

        String value() {
            if (chars) {
                char[] c = new char[data.length];
                for (int i = 0; i < c.length; i++) c[i] = (char) data[i];
                return new String(c);
            }
            byte[] b = new byte[data.length];
            for (int i = 0; i < b.length; i++) b[i] = (byte) data[i];
            return new String(b, StandardCharsets.UTF_8);
        }
    }

    static List<Decoded> decode(MethodNode m) {
        List<Decoded> out = new ArrayList<>();
        Deque<Object> stack = new ArrayDeque<>();
        Map<Integer, Object> locals = new HashMap<>();
        StringBuilder sb = new StringBuilder();
        int line = 0;
        int budget = 200_000;
        for (AbstractInsnNode in = m.instructions.getFirst(); in != null && budget-- > 0; in = in.getNext()) {
            if (in instanceof LineNumberNode ln) {
                line = ln.line;
                continue;
            }
            if (in instanceof LabelNode || in instanceof FrameNode) continue;
            int op = in.getOpcode();
            Integer k = constant(in);
            if (k != null) {
                stack.push(k);
                continue;
            }
            switch (op) {
                case Opcodes.IADD, Opcodes.ISUB, Opcodes.IMUL, Opcodes.IDIV, Opcodes.IREM, Opcodes.ISHL, Opcodes.ISHR, Opcodes.IUSHR,
                     Opcodes.IAND, Opcodes.IOR, Opcodes.IXOR -> {
                    Object b = pop(stack), a = pop(stack);
                    stack.push(a instanceof Integer x && b instanceof Integer y ? arith(op, x, y) : UNKNOWN);
                }
                case Opcodes.INEG -> {
                    Object a = pop(stack);
                    stack.push(a instanceof Integer x ? -x : UNKNOWN);
                }
                case Opcodes.I2C -> {
                    Object a = pop(stack);
                    stack.push(a instanceof Integer x ? x & 0xFFFF : UNKNOWN);
                }
                case Opcodes.I2B -> {
                    Object a = pop(stack);
                    stack.push(a instanceof Integer x ? (int) (byte) (int) x : UNKNOWN);
                }
                case Opcodes.I2S -> {
                    Object a = pop(stack);
                    stack.push(a instanceof Integer x ? (int) (short) (int) x : UNKNOWN);
                }
                case Opcodes.NEWARRAY -> {
                    Object size = pop(stack);
                    int t = ((IntInsnNode) in).operand;
                    if (size instanceof Integer s && s > 0 && s <= 8192 && (t == Opcodes.T_CHAR || t == Opcodes.T_BYTE)) stack.push(new Arr(s, t == Opcodes.T_CHAR));
                    else stack.push(UNKNOWN);
                }
                case Opcodes.DUP -> stack.push(stack.isEmpty() ? UNKNOWN : stack.peek());
                case Opcodes.CASTORE, Opcodes.BASTORE -> {
                    Object v = pop(stack), idx = pop(stack), arr = pop(stack);
                    if (arr instanceof Arr a && idx instanceof Integer i && v instanceof Integer x && i >= 0 && i < a.data.length) {
                        a.data[i] = x;
                        a.stores++;
                    }
                }
                case Opcodes.ASTORE -> locals.put(((VarInsnNode) in).var, pop(stack));
                case Opcodes.ALOAD -> {
                    Object v = locals.get(((VarInsnNode) in).var);
                    stack.push(v instanceof Arr ? v : UNKNOWN);
                }
                case Opcodes.ISTORE -> locals.put(((VarInsnNode) in).var, pop(stack));
                case Opcodes.ILOAD -> {
                    Object v = locals.get(((VarInsnNode) in).var);
                    stack.push(v instanceof Integer ? v : UNKNOWN);
                }
                case Opcodes.POP -> pop(stack);
                case Opcodes.NEW -> {
                    if (((TypeInsnNode) in).desc.equals("java/lang/StringBuilder")) flush(sb, out, line);
                    stack.push(UNKNOWN);
                }
                case Opcodes.INVOKEVIRTUAL, Opcodes.INVOKESPECIAL, Opcodes.INVOKESTATIC -> {
                    MethodInsnNode mi = (MethodInsnNode) in;
                    if (mi.owner.equals("java/lang/StringBuilder") && mi.name.equals("append") && mi.desc.equals("(C)Ljava/lang/StringBuilder;")) {
                        Object v = pop(stack);
                        pop(stack);
                        if (v instanceof Integer x) sb.append((char) (int) x);
                        else flush(sb, out, line);
                        stack.push(UNKNOWN);
                    } else if (mi.owner.equals("java/lang/StringBuilder") && mi.name.equals("toString")) {
                        flush(sb, out, line);
                        stack.clear();
                        stack.push(UNKNOWN);
                    } else if (mi.owner.equals("java/lang/String") && mi.name.equals("<init>") && (mi.desc.startsWith("([C") || mi.desc.startsWith("([B"))) {
                        Object top = pop(stack);
                        if (top instanceof Arr a && a.stores >= a.data.length * 0.7) emit(a.value(), out, line);
                        stack.clear();
                    } else if (mi.owner.equals("java/lang/String") && (mi.name.equals("valueOf") || mi.name.equals("copyValueOf")) && mi.desc.startsWith("([C")) {
                        Object top = pop(stack);
                        if (top instanceof Arr a && a.stores >= a.data.length * 0.7) emit(a.value(), out, line);
                        stack.clear();
                        stack.push(UNKNOWN);
                    } else {
                        stack.clear();
                    }
                }
                default -> stack.clear();
            }
            if (stack.size() > 64) stack.clear();
            if (out.size() > 4000) break;
        }
        flush(sb, out, line);
        return out;
    }

    private static void flush(StringBuilder sb, List<Decoded> out, int line) {
        if (sb.length() >= 2) emit(sb.toString(), out, line);
        sb.setLength(0);
    }

    private static void emit(String s, List<Decoded> out, int line) {
        if (s.length() >= 2 && Analyzer.printableRatio(s) > 0.85) out.add(new Decoded(s, line));
    }

    private static Object pop(Deque<Object> stack) {
        return stack.isEmpty() ? UNKNOWN : stack.pop();
    }

    private static Object arith(int op, int a, int b) {
        return switch (op) {
            case Opcodes.IADD -> a + b;
            case Opcodes.ISUB -> a - b;
            case Opcodes.IMUL -> a * b;
            case Opcodes.IDIV -> b == 0 ? UNKNOWN : a / b;
            case Opcodes.IREM -> b == 0 ? UNKNOWN : a % b;
            case Opcodes.ISHL -> a << b;
            case Opcodes.ISHR -> a >> b;
            case Opcodes.IUSHR -> a >>> b;
            case Opcodes.IAND -> a & b;
            case Opcodes.IOR -> a | b;
            case Opcodes.IXOR -> a ^ b;
            default -> UNKNOWN;
        };
    }

    private static Integer constant(AbstractInsnNode n) {
        int op = n.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) return op - Opcodes.ICONST_0;
        if (n instanceof IntInsnNode ii && (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH)) return ii.operand;
        if (n instanceof LdcInsnNode l && l.cst instanceof Integer v) return v;
        return null;
    }
}
