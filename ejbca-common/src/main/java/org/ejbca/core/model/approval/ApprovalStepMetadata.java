package org.ejbca.core.model.approval;

import java.io.Serializable;
import java.util.List;

/**
 * Holds data of metadata of an approval step.
 *
 * @version $Id: ApprovalStepMetadata.java 26057 2017-06-22 08:08:34Z anatom $
 */
public class ApprovalStepMetadata implements Serializable {
  private static final long serialVersionUID = -8320579875930271365L;

  /** Config. */
  public static final int METADATATYPE_CHECKBOX = 1;
  /** Config. */
  public static final int METADATATYPE_RADIOBUTTON = 2;
  /** Config. */
  public static final int METADATATYPE_TEXTBOX = 3;
  /** ID. */
  private final int metadataId;
  /** Instructions. */
  private String instruction;
  /** Options. */
  private List<String> options;
  /** Type. */
  private int optionsType;
  /** Value. */
  private String optionValue;
  /** Note. */
  private String optionNote;

  /**
   * @param id ID
   * @param anInstruction Instruction
   * @param theOptions Options
   * @param type Type
   */
  public ApprovalStepMetadata(
      final int id,
      final String anInstruction,
      final List<String> theOptions,
      final int type) {
    this.metadataId = id;
    this.instruction = anInstruction;
    this.options = theOptions;
    this.optionsType = type;
    this.optionValue = "";
    this.optionNote = "";
  }

  /**
   * @return ID
   */
  public int getMetadataId() {
    return metadataId;
  }

  /**
   * @return Instruction
   */
  public String getInstruction() {
    return instruction;
  }

  /**
   * @param anInstruction Instruction
   */
  public void setDescription(final String anInstruction) {
    this.instruction = anInstruction;
  }

  /**
   * @return Options
   */
  public List<String> getOptions() {
    return options;
  }

  /**
   * @param theOptions Options
   */
  public void setOptions(final List<String> theOptions) {
    this.options = theOptions;
  }

  /**
   * @return Type
   */
  public int getOptionsType() {
    return optionsType;
  }

  /**
   * @param type Type
   */
  public void setOptionsType(final int type) {
    optionsType = type;
  }

  /**
   * @return Value
   */
  public String getOptionValue() {
    return optionValue;
  }

  /**
   * @param value Value
   */
  public void setOptionValue(final String value) {
    optionValue = value;
  }

  /**
   * @return Note
   */
  public String getOptionNote() {
    return optionNote;
  }
  /**
   * @param note Note
   */
  public void setOptionNote(final String note) {
    optionNote = note;
  }
}
